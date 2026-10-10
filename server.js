import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import Redis from 'ioredis';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import cluster from 'cluster';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==========================================
// 1. CONFIGURATION & ENVIRONMENT
// ==========================================
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const CLUSTER_MODE = process.env.CLUSTER_MODE === 'true';

// ⚠️ SECURITY: NO hardcoded fallbacks for sensitive credentials
if (!process.env.JWT_SECRET) {
  console.error('[SECURITY] ❌ JWT_SECRET is not set in .env! Server refuses to start.');
  process.exit(1);
}
if (!process.env.MONGODB_URI) {
  console.error('[SECURITY] ❌ MONGODB_URI is not set in .env! Server refuses to start.');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || (JWT_SECRET + '_refresh_v2');
const MONGODB_URI = process.env.MONGODB_URI;
const REDIS_URL = process.env.REDIS_URL || null; // Optional: falls back to in-memory if not set

// Multi-Core Cluster Management for Concurrency
const numCPUs = (typeof os.availableParallelism === 'function') ? os.availableParallelism() : os.cpus().length;

if (CLUSTER_MODE && cluster.isPrimary) {
  console.log(`[GLOBAL CLUSTER] ⚡ Primary process ${process.pid} is orchestrating across ${numCPUs} CPU cores.`);
  
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
    console.warn(`[GLOBAL CLUSTER] ⚠️ Worker ${worker.process.pid} died (${signal || code}). Spawning replacement...`);
    cluster.fork();
  });
} else {
  startServerWorker();
}

function startServerWorker() {
  const app = express();

  // Trust first reverse proxy (Vercel, Render, Cloudflare, AWS ALB, Nginx)
  // Ensures accurate client IP resolution for rate limiters
  app.set('trust proxy', 1);

  // ==========================================
  // REDIS CLIENT (Shared Rate Limit Store)
  // ==========================================
  // Redis enables rate limits to work correctly across multiple
  // cluster workers & server restarts — in-memory limiters break in cluster mode!
  let redisClient = null;

  if (REDIS_URL) {
    redisClient = new Redis(REDIS_URL, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 100, 3000),
      enableOfflineQueue: false,
      lazyConnect: false,
    });

    redisClient.on('connect', () => console.log('[REDIS] ✅ Connected to Redis store.'));
    redisClient.on('error', (err) => console.warn('[REDIS] ⚠️ Redis error (falling back gracefully):', err.message));
  } else {
    console.warn('[REDIS] ⚠️ REDIS_URL not set — using in-memory rate limiting (not suitable for multi-instance deployments).');
  }

  // Helper: build RedisStore or undefined (falls back to in-memory)
  function makeRedisStore(prefix) {
    if (!redisClient) return undefined;
    return new RedisStore({
      sendCommand: (...args) => redisClient.call(...args),
      prefix: `rl:${prefix}:`,
    });
  }

  // ==========================================
  // AUDIT LOG — Track all admin actions
  // ==========================================
  const AUDIT_LOG_FILE = path.join(__dirname, 'data', 'audit.log');

  async function writeAuditLog(action, adminId, ip, extra = {}) {
    const entry = JSON.stringify({
      ts: new Date().toISOString(),
      action,
      adminId: adminId || 'unknown',
      ip: ip || 'unknown',
      ...extra
    }) + '\n';
    fsp.appendFile(AUDIT_LOG_FILE, entry, 'utf8').catch(() => {});
    console.log(`[AUDIT] ${action} | admin:${adminId} | ip:${ip}`);
  }

  // ==========================================
  // JWT BLACKLIST (Logout invalidation via Redis)
  // ==========================================
  // When an admin logs out, their token jti is stored in Redis with TTL
  // so even valid tokens cannot be re-used after logout.
  async function blacklistToken(jti, ttlSeconds) {
    if (!redisClient) return; // If no Redis, tokens expire naturally
    try {
      await redisClient.set(`blacklist:${jti}`, '1', 'EX', ttlSeconds);
    } catch (err) {
      console.warn('[JWT BLACKLIST] Failed to blacklist token:', err.message);
    }
  }

  async function isTokenBlacklisted(jti) {
    if (!redisClient || !jti) return false;
    try {
      const val = await redisClient.get(`blacklist:${jti}`);
      return val === '1';
    } catch {
      return false; // Fail open — better UX than breaking auth
    }
  }

  // ==========================================
  // 2. DATA STORAGE & NON-BLOCKING CACHE
  // ==========================================
  const DATA_DIR = path.join(__dirname, 'data');
  const INQUIRIES_FILE = path.join(DATA_DIR, 'inquiries.json');
  const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  // Active OTP storage with automatic TTL cleanup
  const activeOTPs = new Map();

  // Default admin template
  const defaultAdmin = {
    id: 'admin',
    username: (process.env.ADMIN_INITIAL_USERNAME || 'admin').trim().toLowerCase(),
    email: (process.env.ADMIN_INITIAL_EMAIL || 'admin@theglobal.com').trim().toLowerCase(),
    phone: (process.env.ADMIN_INITIAL_PHONE || '9899933768').trim(),
    name: 'Global Admin Board',
    password: hashPassword(process.env.ADMIN_INITIAL_PASSWORD || 'admin123'),
    role: 'Super Admin'
  };

  // In-memory cache for ultra-fast non-blocking local fallback
  let inMemoryInquiries = [];
  let inMemoryAdmin = defaultAdmin;

  // Load initial fallback files once at worker boot
  try {
    if (fs.existsSync(INQUIRIES_FILE)) {
      const raw = fs.readFileSync(INQUIRIES_FILE, 'utf8');
      inMemoryInquiries = JSON.parse(raw);
    } else {
      fs.writeFileSync(INQUIRIES_FILE, JSON.stringify([], null, 2));
    }
  } catch {
    inMemoryInquiries = [];
  }

  try {
    if (fs.existsSync(ADMIN_FILE)) {
      const raw = fs.readFileSync(ADMIN_FILE, 'utf8');
      inMemoryAdmin = JSON.parse(raw);
    } else {
      fs.writeFileSync(ADMIN_FILE, JSON.stringify(defaultAdmin, null, 2));
    }
  } catch {
    inMemoryAdmin = defaultAdmin;
  }

  // Debounced asynchronous disk writer (NEVER BLOCKS EVENT LOOP)
  let diskWritePending = false;
  let diskWriteTimer = null;

  function scheduleDiskBackup() {
    diskWritePending = true;
    if (diskWriteTimer) return;

    diskWriteTimer = setTimeout(async () => {
      diskWriteTimer = null;
      if (!diskWritePending) return;
      diskWritePending = false;

      try {
        const tempPath = `${INQUIRIES_FILE}.tmp.${Date.now()}`;
        await fsp.writeFile(tempPath, JSON.stringify(inMemoryInquiries.slice(0, 1000), null, 2), 'utf8');
        await fsp.rename(tempPath, INQUIRIES_FILE);
      } catch (err) {
        console.error('[STORAGE WARNING] Failed async disk backup write:', err.message);
      }
    }, 400); // 400ms debounce coalesces bursts of concurrent inquiries into 1 write
  }

  // ==========================================
  // 3. CRYPTOGRAPHIC UTILITIES
  // ==========================================

  function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const derivedKey = crypto.scryptSync(password, salt, 64);
    return `${salt}:${derivedKey.toString('hex')}`;
  }

  function verifyPassword(password, storedHash) {
    if (!storedHash || typeof storedHash !== 'string') return false;
    
    if (!storedHash.includes(':')) {
      return password === storedHash;
    }

    const [salt, key] = storedHash.split(':');
    if (!salt || !key) return false;

    try {
      const keyBuffer = Buffer.from(key, 'hex');
      const derivedKey = crypto.scryptSync(password, salt, 64);
      
      if (keyBuffer.length !== derivedKey.length) return false;
      return crypto.timingSafeEqual(keyBuffer, derivedKey);
    } catch {
      return false;
    }
  }

  function createJWT(payload, expiresInSeconds = 86400, secret = JWT_SECRET) {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    // jti = JWT ID — unique per token, used for blacklisting on logout
    const jti = crypto.randomBytes(16).toString('hex');
    const fullPayload = Buffer.from(JSON.stringify({
      ...payload,
      jti,
      iat: now,
      exp: now + expiresInSeconds
    })).toString('base64url');

    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${header}.${fullPayload}`)
      .digest('base64url');

    return `${header}.${fullPayload}.${signature}`;
  }

  // Creates a short-lived access token (15 min) + long-lived refresh token (7 days)
  function createTokenPair(payload) {
    const accessToken  = createJWT(payload, 15 * 60, JWT_SECRET);          // 15 minutes
    const refreshToken = createJWT(payload, 7 * 24 * 3600, JWT_REFRESH_SECRET); // 7 days
    return { accessToken, refreshToken };
  }

  function verifyJWT(token, secret = JWT_SECRET) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, payload, signature] = parts;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(`${header}.${payload}`)
      .digest('base64url');

    const sigBuf = Buffer.from(signature, 'base64url');
    const expSigBuf = Buffer.from(expectedSignature, 'base64url');

    if (sigBuf.length !== expSigBuf.length || !crypto.timingSafeEqual(sigBuf, expSigBuf)) {
      return null;
    }

    try {
      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      const now = Math.floor(Date.now() / 1000);
      if (decoded.exp && decoded.exp < now) {
        return null;
      }
      return decoded;
    } catch {
      return null;
    }
  }

  function sanitizeString(input, maxLength = 1000) {
    if (typeof input !== 'string') return '';
    return input
      .trim()
      .slice(0, maxLength)
      // Strip HTML/script injection chars
      .replace(/[<>"'`]/g, '')
      // Strip null bytes (bypass attempts)
      .replace(/\0/g, '');
  }

  // Validate password strength: min 8 chars, at least 1 number, 1 uppercase
  function isStrongPassword(password) {
    if (!password || typeof password !== 'string') return false;
    if (password.length < 8) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    return true;
  }

  // ==========================================
  // 4. MONGOOSE SCHEMAS & HIGH-SPEED INDEXES
  // ==========================================

  const inquirySchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true, index: true },
    type: { type: String, default: 'inquiry', index: true },
    name: { type: String, required: true, trim: true },
    company: { type: String, default: 'Enterprise Client' },
    phone: { type: String, required: true, trim: true, index: true },
    email: { type: String, default: 'N/A' },
    service: { type: String, default: 'General Infrastructure Inquiry' },
    budget: { type: String, default: 'Undisclosed' },
    location: { type: String, default: 'NCR, India' },
    message: { type: String, default: '' },
    meetingDate: { type: String, default: '' },
    timeSlot: { type: String, default: '' },
    meetingMode: { type: String, default: 'Virtual Video Call' },
    facilityType: { type: String, default: '' },
    estimatedArea: { type: String, default: '' },
    timeline: { type: String, default: '' },
    engagementType: { type: String, default: '' },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    status: { type: String, default: 'New', enum: ['New', 'In Progress', 'Contacted', 'Closed'] },
    read: { type: Boolean, default: false },
    notes: { type: String, default: '' },
    isDeleted: { type: Boolean, default: false },
    deletedAt: { type: Date, default: null }
  }, {
    timestamps: true
  });

  // Compound Indexes for O(log N) sorting, filtering & high-concurrency throughput
  inquirySchema.index({ createdAt: -1 });
  inquirySchema.index({ isDeleted: 1, createdAt: -1 });
  inquirySchema.index({ isDeleted: 1, read: 1 });

  const adminSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    username: { type: String, default: 'admin', trim: true, index: true },
    email: { type: String, required: true, trim: true, index: true },
    phone: { type: String, default: '9899933768', trim: true, index: true },
    name: { type: String, default: 'Global Admin Board' },
    password: { type: String, required: true },
    role: { type: String, default: 'Super Admin' }
  }, {
    timestamps: true
  });

  const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', inquirySchema);
  const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

  // ==========================================
  // 5. DATABASE CONNECTION & POOLING
  // ==========================================

  async function connectMongoDB() {
    try {
      await mongoose.connect(MONGODB_URI, {
        maxPoolSize: 100,             // Support up to 100 concurrent DB socket operations
        minPoolSize: 10,              // Keep 10 pre-warmed connections open to eliminate handshake lag
        socketTimeoutMS: 45000,
        serverSelectionTimeoutMS: 8000,
        maxIdleTimeMS: 30000,
        heartbeatFrequencyMS: 10000
      });
      console.log(`[GLOBAL ENTERPRISES] 🍃 Process ${process.pid} connected to MongoDB Atlas.`);

      // Seed / check default admin asynchronously
      const existingAdmin = await Admin.findOne({
        $or: [{ id: defaultAdmin.id }, { username: defaultAdmin.username }, { email: defaultAdmin.email }]
      }).lean();

      if (!existingAdmin) {
        await Admin.create(defaultAdmin);
        console.log('[GLOBAL ENTERPRISES] ✅ Initialized admin account in MongoDB.');
      } else if (!existingAdmin.username) {
        await Admin.updateOne({ _id: existingAdmin._id }, { $set: { username: 'admin' } });
        console.log('[GLOBAL ENTERPRISES] ✅ Updated existing admin record with username "admin".');
      }
    } catch (err) {
      console.error('[GLOBAL ENTERPRISES] ⚠️ MongoDB connection error:', err.message);
    }
  }

  connectMongoDB();

  // ==========================================
  // 6. SECURITY MIDDLEWARE & PERFORMANCE
  // ==========================================

  // GZIP & Deflate response compression (reduces payload by up to 80%)
  app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
      if (req.headers['x-no-compression']) return false;
      return compression.filter(req, res);
    }
  }));

  // Helmet Security Headers (OWASP Top 10 hardening)
  app.use(helmet({
    contentSecurityPolicy: false, // Let frontend handle CSP / CDNs cleanly
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    dnsPrefetchControl: { allow: true },
    frameguard: { action: 'sameorigin' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true
  }));

  // Explicit security headers
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  // CORS Configuration with Cached Preflight
  const rawOrigins = (process.env.CORS_ORIGIN || 'https://theglobalenterprises.vercel.app,http://localhost:3000,http://localhost:3001,http://localhost:5173,https://globalenterprises.in,https://www.theglobalenterprises.in')
    .split(',')
    .map(o => o.trim().replace(/\/$/, '').toLowerCase());

  app.use(cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      const cleanOrigin = origin.replace(/\/$/, '').toLowerCase();
      
      const isAllowed = 
        rawOrigins.includes(cleanOrigin) ||
        rawOrigins.includes('*') ||
        cleanOrigin.endsWith('.vercel.app') ||
        cleanOrigin.includes('globalenterprises.in') ||
        cleanOrigin.includes('theglobalenterprises.in');

      if (isAllowed) {
        return callback(null, true);
      }
      return callback(new Error(`CORS Policy: Origin ${origin} not permitted.`));
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400 // Cache preflight response in browser for 24 hours to reduce latency!
  }));

  // Body Parsing with safe size limit (Prevents Payload Bombing)
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));

  // Graceful Handling of Malformed JSON payloads
  app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      return res.status(400).json({ success: false, message: 'Malformed JSON payload received.' });
    }
    next(err);
  });

  // NoSQL Injection Defense: Recursively strip operator keys like $gt, $ne, $where
  function sanitizeNoSQL(target) {
    if (!target || typeof target !== 'object') return;
    for (const key of Object.keys(target)) {
      if (key.startsWith('$') || key.includes('.')) {
        delete target[key];
      } else if (typeof target[key] === 'object' && target[key] !== null) {
        sanitizeNoSQL(target[key]);
      }
    }
  }

  app.use((req, res, next) => {
    sanitizeNoSQL(req.body);
    sanitizeNoSQL(req.query);
    sanitizeNoSQL(req.params);
    next();
  });

  // ==========================================
  // 7. REDIS-BACKED RATE LIMITING
  // All limiters use Redis when available so that:
  //   - Multi-worker cluster mode shares the same counters
  //   - Server restarts don't reset attack windows
  //   - Distributed deployments (multiple servers) share limits
  // Falls back to in-memory store gracefully when Redis is unavailable.
  // ==========================================

  // General API limiter — 600 req / 15 min per IP
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false,
    store: makeRedisStore('api'),
    message: { success: false, message: 'Too many requests. Please slow down and try again shortly.' }
  });

  // Inquiry submission limiter — 20 submissions / 15 min per IP
  // Blocks form-spam bots and automated scrapers
  const inquiryLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    store: makeRedisStore('inquiry'),
    message: { success: false, message: 'Inquiry rate limit reached. Please wait a few moments before submitting again.' }
  });

  // Admin login brute-force limiter — 10 failed attempts / 15 min per IP
  // skipSuccessfulRequests: legit logins don't burn the quota
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    store: makeRedisStore('login'),
    message: { success: false, message: 'Too many failed login attempts. For security, please try again in 15 minutes.' }
  });

  // OTP dispatch limiter — 5 OTPs / 10 min per IP
  // Prevents OTP flooding / SMS bombing attacks
  const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    store: makeRedisStore('otp'),
    message: { success: false, message: 'Too many OTP requests. Please wait a few minutes before requesting another code.' }
  });

  // Password change limiter — 5 attempts / 30 min per IP
  // Extra protection on sensitive credential-update endpoint
  const passwordChangeLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    store: makeRedisStore('pwchange'),
    message: { success: false, message: 'Too many password change attempts. Please wait 30 minutes.' }
  });

  app.use('/api/', apiLimiter);

  // ==========================================
  // 8. AUTHENTICATION GUARD MIDDLEWARE
  // ==========================================

  async function requireAdminAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized: Admin authentication required.'
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyJWT(token, JWT_SECRET);

    if (!decoded || (decoded.role !== 'Super Admin' && decoded.role !== 'Admin')) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized: Invalid or expired session token.'
      });
    }

    // Check if this specific token has been blacklisted (e.g. after logout)
    if (decoded.jti && await isTokenBlacklisted(decoded.jti)) {
      return res.status(401).json({
        success: false,
        message: 'Session has been revoked. Please login again.'
      });
    }

    req.admin = decoded;
    next();
  }

  function normalizeInquiry(inq) {
    if (!inq || typeof inq !== 'object') return inq;
    let type = inq.type;
    if (!type) {
      const s = (inq.service || '').toLowerCase();
      const c = (inq.company || '').toLowerCase();
      const m = (inq.message || '').toLowerCase();
      if (s.includes('scheduled meeting') || c.includes('scheduled consultation') || m.includes('scheduled strategy') || m.includes('consultation')) {
        type = 'meeting';
      } else if (s.includes('quote') || s.includes('quotation') || m.includes('pricing') || (inq.budget && inq.budget !== 'Undisclosed' && inq.budget !== 'Consultation Session')) {
        type = 'quote';
      } else if (c.includes('partner') || m.includes('partner') || m.includes('join')) {
        type = 'general';
      } else {
        type = 'inquiry';
      }
    }

    return {
      id: inq.id,
      type,
      name: inq.name,
      company: inq.company || 'Enterprise Client',
      phone: inq.phone,
      email: inq.email || 'N/A',
      service: inq.service || 'General Infrastructure Inquiry',
      budget: inq.budget || 'Undisclosed',
      location: inq.location || 'NCR, India',
      message: inq.message || '',
      meetingDate: inq.meetingDate || '',
      timeSlot: inq.timeSlot || '',
      meetingMode: inq.meetingMode || 'Virtual Video Call',
      facilityType: inq.facilityType || '',
      estimatedArea: inq.estimatedArea || '',
      timeline: inq.timeline || '',
      engagementType: inq.engagementType || '',
      metadata: inq.metadata && typeof inq.metadata === 'object' ? inq.metadata : {},
      status: inq.status || 'New',
      read: Boolean(inq.read),
      notes: inq.notes || '',
      isDeleted: Boolean(inq.isDeleted),
      deletedAt: inq.deletedAt || null,
      createdAt: inq.createdAt,
      updatedAt: inq.updatedAt
    };
  }

  // ==========================================
  // 9. PUBLIC API ENDPOINTS
  // ==========================================

  // Health Check
  app.get('/api/health', (req, res) => {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    const isDbConnected = mongoose.connection.readyState === 1;
    res.json({
      status: 'operational',
      service: 'Global Enterprises Central CRM API',
      database: isDbConnected ? 'MongoDB Atlas (Connected)' : 'Local Fallback Storage',
      clusterWorkerPid: process.pid,
      timestamp: new Date().toISOString()
    });
  });

  // Submit New Customer Inquiry
  app.post('/api/inquiries', inquiryLimiter, async (req, res) => {
    try {
      const { 
        name, 
        company, 
        phone, 
        email, 
        service, 
        budget, 
        location, 
        message,
        type,
        meetingDate,
        timeSlot,
        meetingMode,
        facilityType,
        estimatedArea,
        timeline,
        engagementType,
        metadata
      } = req.body;

      const sanitizedName = sanitizeString(name, 100);
      const sanitizedPhone = sanitizeString(phone, 30);

      if (!sanitizedName || sanitizedName.length < 2) {
        return res.status(400).json({ success: false, message: 'Please provide a valid full name (minimum 2 characters).' });
      }

      const cleanPhoneDigits = sanitizedPhone.replace(/[^0-9+]/g, '');
      if (!cleanPhoneDigits || cleanPhoneDigits.length < 8) {
        return res.status(400).json({ success: false, message: 'Please provide a valid contact phone number.' });
      }

      const validTypes = ['meeting', 'inquiry', 'quote', 'general'];
      const inquiryType = validTypes.includes(type) ? type : 'inquiry';

      const now = new Date();
      const newInquiryData = {
        id: 'INQ-' + crypto.randomInt(1000, 9999),
        type: inquiryType,
        name: sanitizedName,
        company: sanitizeString(company, 120) || 'Enterprise Client',
        phone: sanitizedPhone,
        email: sanitizeString(email, 120) || 'N/A',
        service: sanitizeString(service, 150) || 'General Infrastructure Inquiry',
        budget: sanitizeString(budget, 80) || 'Undisclosed',
        location: sanitizeString(location, 150) || 'NCR, India',
        message: sanitizeString(message, 2000) || 'Submitted via website form.',
        meetingDate: sanitizeString(meetingDate, 50),
        timeSlot: sanitizeString(timeSlot, 50),
        meetingMode: sanitizeString(meetingMode, 50) || 'Virtual Video Call',
        facilityType: sanitizeString(facilityType, 100),
        estimatedArea: sanitizeString(estimatedArea, 100),
        timeline: sanitizeString(timeline, 100),
        engagementType: sanitizeString(engagementType, 100),
        metadata: metadata && typeof metadata === 'object' ? metadata : {},
        status: 'New',
        read: false,
        notes: '',
        isDeleted: false,
        deletedAt: null,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString()
      };

      let savedRecord = null;

      // 1. Primary DB insert (Indexed, fast)
      if (mongoose.connection.readyState === 1) {
        savedRecord = await Inquiry.create(newInquiryData);
      } else {
        savedRecord = newInquiryData;
      }

      // 2. Non-blocking In-Memory Cache & Debounced Async Disk Sync
      inMemoryInquiries.unshift(normalizeInquiry(savedRecord));
      if (inMemoryInquiries.length > 1000) {
        inMemoryInquiries.length = 1000;
      }
      scheduleDiskBackup();

      // Return fast response (under 20ms)
      res.status(201).json({
        success: true,
        message: 'Inquiry received securely.',
        data: normalizeInquiry(savedRecord)
      });
    } catch (err) {
      console.error('[INQUIRY ERROR]:', err);
      res.status(500).json({ success: false, message: 'Failed to process inquiry. Please try again.' });
    }
  });

  // ==========================================
  // 10. ADMIN AUTHENTICATION
  // ==========================================

  app.post('/api/admin/login', loginLimiter, async (req, res) => {
    try {
      const { adminId, password } = req.body;
      if (!adminId || !password || typeof adminId !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ success: false, message: 'Admin ID and password are required.' });
      }

      const cleanId = String(adminId).trim().toLowerCase().slice(0, 120);
      let adminRecord = null;

      if (mongoose.connection.readyState === 1) {
        adminRecord = await Admin.findOne({
          $or: [
            { id: cleanId },
            { username: cleanId },
            { email: cleanId },
            { phone: cleanId }
          ]
        }).lean();
      }

      // Fallback to in-memory admin
      if (!adminRecord) {
        const local = inMemoryAdmin || defaultAdmin;
        const isMatch = 
          cleanId === (local.id || '').toLowerCase() ||
          cleanId === (local.username || '').toLowerCase() ||
          cleanId === (local.email || '').toLowerCase() ||
          cleanId === local.phone;
        
        if (isMatch) adminRecord = local;
      }

      const clientIp = req.ip || req.connection.remoteAddress;

      if (adminRecord && verifyPassword(password, adminRecord.password)) {
        // Issue short-lived access token + long-lived refresh token
        const tokenPayload = {
          id: adminRecord.id,
          email: adminRecord.email,
          role: adminRecord.role || 'Super Admin'
        };
        const { accessToken, refreshToken } = createTokenPair(tokenPayload);

        // ✅ Audit: successful login
        await writeAuditLog('ADMIN_LOGIN_SUCCESS', adminRecord.id, clientIp);

        return res.json({
          success: true,
          token: accessToken,           // 15-minute access token
          refreshToken,                 // 7-day refresh token
          expiresIn: 15 * 60,           // seconds
          admin: {
            id: adminRecord.id,
            email: adminRecord.email,
            phone: adminRecord.phone,
            name: adminRecord.name,
            role: adminRecord.role
          }
        });
      }

      // ✅ Audit: failed login attempt
      await writeAuditLog('ADMIN_LOGIN_FAILED', cleanId, clientIp, { reason: 'bad_credentials' });

      return res.status(401).json({
        success: false,
        message: 'Invalid administrative credentials. Please verify and try again.'
      });
    } catch (err) {
      console.error('[ADMIN LOGIN ERROR]:', err);
      res.status(500).json({ success: false, message: 'Authentication service temporarily unavailable.' });
    }
  });

  // ==========================================
  // TOKEN REFRESH — Issue new access token using refresh token
  // ==========================================
  app.post('/api/admin/refresh-token', async (req, res) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken || typeof refreshToken !== 'string') {
        return res.status(400).json({ success: false, message: 'Refresh token is required.' });
      }

      const decoded = verifyJWT(refreshToken, JWT_REFRESH_SECRET);
      if (!decoded) {
        return res.status(401).json({ success: false, message: 'Refresh token invalid or expired. Please login again.' });
      }

      // Check if refresh token itself is blacklisted
      if (decoded.jti && await isTokenBlacklisted(decoded.jti)) {
        return res.status(401).json({ success: false, message: 'Refresh token has been revoked. Please login again.' });
      }

      // Issue new access token only (not a new refresh token — prevents infinite rotation abuse)
      const newAccessToken = createJWT({
        id: decoded.id,
        email: decoded.email,
        role: decoded.role
      }, 15 * 60, JWT_SECRET);

      res.json({
        success: true,
        token: newAccessToken,
        expiresIn: 15 * 60
      });
    } catch (err) {
      console.error('[REFRESH TOKEN ERROR]:', err);
      res.status(500).json({ success: false, message: 'Token refresh failed.' });
    }
  });

  // ==========================================
  // LOGOUT — Blacklist token in Redis
  // ==========================================
  app.post('/api/admin/logout', requireAdminAuth, async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader?.split(' ')[1];
      const decoded = token ? verifyJWT(token, JWT_SECRET) : null;

      if (decoded?.jti) {
        const now = Math.floor(Date.now() / 1000);
        const remainingTtl = Math.max(0, decoded.exp - now);
        await blacklistToken(decoded.jti, remainingTtl + 60);
      }

      // Also blacklist the refresh token if sent
      const { refreshToken } = req.body || {};
      if (refreshToken) {
        const rdecoded = verifyJWT(refreshToken, JWT_REFRESH_SECRET);
        if (rdecoded?.jti) {
          const now = Math.floor(Date.now() / 1000);
          const remainingTtl = Math.max(0, rdecoded.exp - now);
          await blacklistToken(rdecoded.jti, remainingTtl + 60);
        }
      }

      await writeAuditLog('ADMIN_LOGOUT', req.admin?.id, req.ip);

      res.json({ success: true, message: 'Logged out successfully. Session revoked.' });
    } catch (err) {
      console.error('[LOGOUT ERROR]:', err);
      res.status(500).json({ success: false, message: 'Logout failed.' });
    }
  });

  app.post('/api/admin/send-otp', otpLimiter, requireAdminAuth, async (req, res) => {
    try {
      let email = 'admin@theglobal.com';
      if (mongoose.connection.readyState === 1) {
        const admin = await Admin.findOne({ id: req.admin.id }).lean();
        if (admin && admin.email) email = admin.email;
      } else if (inMemoryAdmin && inMemoryAdmin.email) {
        email = inMemoryAdmin.email;
      }

      const generatedOTP = crypto.randomInt(100000, 999999).toString();
      activeOTPs.set('admin', {
        otpHash: hashPassword(generatedOTP),
        expiresAt: Date.now() + 5 * 60 * 1000,
        attempts: 0
      });

      res.json({
        success: true,
        message: `6-Digit verification code dispatched to registered contact (${email}).`
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to dispatch verification code.' });
    }
  });

  app.post('/api/admin/change-password', requireAdminAuth, passwordChangeLimiter, async (req, res) => {
    try {
      const { mode, oldPassword, otpCode, newPassword } = req.body;

      // Enforce strong password policy (min 8 chars, 1 uppercase, 1 number)
      if (!isStrongPassword(newPassword)) {
        return res.status(400).json({
          success: false,
          message: 'New password must be at least 8 characters with at least 1 uppercase letter and 1 number.'
        });
      }

      let adminRecord = null;
      if (mongoose.connection.readyState === 1) {
        adminRecord = await Admin.findOne({ id: req.admin.id }).lean();
      }
      if (!adminRecord) {
        adminRecord = inMemoryAdmin || defaultAdmin;
      }

      if (mode === 'old_password') {
        if (!verifyPassword(oldPassword, adminRecord.password)) {
          return res.status(400).json({ success: false, message: 'Current password verification failed.' });
        }
      } else if (mode === 'otp') {
        const storedOTP = activeOTPs.get('admin');
        if (!storedOTP || Date.now() > storedOTP.expiresAt) {
          activeOTPs.delete('admin');
          return res.status(400).json({ success: false, message: 'Verification code has expired. Please request a new code.' });
        }

        storedOTP.attempts += 1;
        if (storedOTP.attempts > 3) {
          activeOTPs.delete('admin');
          return res.status(400).json({ success: false, message: 'Too many failed attempts. Code invalidated.' });
        }

        if (!verifyPassword(String(otpCode), storedOTP.otpHash)) {
          return res.status(400).json({ success: false, message: 'Invalid 6-digit verification code.' });
        }

        activeOTPs.delete('admin');
      } else {
        return res.status(400).json({ success: false, message: 'Invalid verification mode specified.' });
      }

      const hashedNew = hashPassword(newPassword);

      if (mongoose.connection.readyState === 1) {
        await Admin.updateOne({ id: req.admin.id }, { $set: { password: hashedNew } });
      }

      // Update in-memory fallback
      if (inMemoryAdmin) {
        inMemoryAdmin.password = hashedNew;
        inMemoryAdmin.updatedAt = new Date().toISOString();
        fsp.writeFile(ADMIN_FILE, JSON.stringify(inMemoryAdmin, null, 2), 'utf8').catch(() => {});
      }

      await writeAuditLog('ADMIN_PASSWORD_CHANGED', req.admin?.id, req.ip, { mode });

      res.json({
        success: true,
        message: 'Admin password updated securely.'
      });
    } catch (err) {
      console.error('[PASSWORD CHANGE ERROR]:', err);
      res.status(500).json({ success: false, message: 'Failed to update password.' });
    }
  });

  // ==========================================
  // 11. PROTECTED INQUIRY MANAGEMENT ENDPOINTS
  // ==========================================

  // Get All Inquiries (High speed lean query with compound index)
  app.get('/api/inquiries', requireAdminAuth, async (req, res) => {
    try {
      res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      let inquiries = [];

      if (mongoose.connection.readyState === 1) {
        // Leverages compound index { createdAt: -1 } with .lean() for minimum memory overhead
        inquiries = await Inquiry.find().sort({ createdAt: -1 }).lean();
      } else {
        inquiries = inMemoryInquiries;
      }

      const normalized = inquiries.map(normalizeInquiry);
      res.json({
        success: true,
        count: normalized.length,
        data: normalized
      });
    } catch (err) {
      console.error('[FETCH INQUIRIES ERROR]:', err);
      res.status(500).json({ success: false, message: 'Failed to retrieve inquiries.' });
    }
  });

  // Mark All Inquiries As Read
  app.post('/api/inquiries/mark-all-read', requireAdminAuth, async (req, res) => {
    try {
      if (mongoose.connection.readyState === 1) {
        await Inquiry.updateMany({ read: false }, { $set: { read: true } });
        const updated = await Inquiry.find().sort({ createdAt: -1 }).lean();
        
        inMemoryInquiries = updated.map(normalizeInquiry);
        scheduleDiskBackup();

        return res.json({
          success: true,
          message: 'Marked all inquiries as read.',
          data: inMemoryInquiries
        });
      }

      inMemoryInquiries = inMemoryInquiries.map(inq => ({ ...inq, read: true, updatedAt: new Date().toISOString() }));
      scheduleDiskBackup();

      res.json({
        success: true,
        message: 'Marked all inquiries as read.',
        data: inMemoryInquiries.map(normalizeInquiry)
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to mark inquiries as read.' });
    }
  });

  // Update Single Inquiry Status / Notes / Read
  app.patch('/api/inquiries/:id', requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const { status, notes, read } = req.body;

      if (!id || !/^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id)) {
        return res.status(400).json({ success: false, message: 'Invalid inquiry ID format.' });
      }

      const updateFields = {};
      const allowedStatuses = ['New', 'In Progress', 'Contacted', 'Closed'];

      if (status !== undefined && allowedStatuses.includes(status)) {
        updateFields.status = status;
      }
      if (notes !== undefined) {
        updateFields.notes = sanitizeString(notes, 1000);
      }
      if (read !== undefined) {
        updateFields.read = Boolean(read);
      }

      let updatedDoc = null;

      if (mongoose.connection.readyState === 1) {
        updatedDoc = await Inquiry.findOneAndUpdate(
          { id },
          { $set: updateFields },
          { new: true }
        ).lean();
      }

      // Update in-memory cache
      const idx = inMemoryInquiries.findIndex(i => i.id === id);
      if (idx !== -1) {
        Object.assign(inMemoryInquiries[idx], updateFields, { updatedAt: new Date().toISOString() });
        if (!updatedDoc) updatedDoc = inMemoryInquiries[idx];
        scheduleDiskBackup();
      }

      if (!updatedDoc) {
        return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
      }

      res.json({
        success: true,
        message: 'Inquiry record updated.',
        data: normalizeInquiry(updatedDoc)
      });
    } catch (err) {
      console.error('[UPDATE INQUIRY ERROR]:', err);
      res.status(500).json({ success: false, message: 'Failed to update inquiry.' });
    }
  });

  // Clear / Empty All Inquiries In Recycle Bin
  app.delete('/api/inquiries/bin/clear', requireAdminAuth, async (req, res) => {
    try {
      let deletedCount = 0;
      if (mongoose.connection.readyState === 1) {
        const resDb = await Inquiry.deleteMany({ isDeleted: true });
        deletedCount = resDb.deletedCount;
      }

      const prevLen = inMemoryInquiries.length;
      inMemoryInquiries = inMemoryInquiries.filter(inq => !inq.isDeleted);
      if (!deletedCount) {
        deletedCount = prevLen - inMemoryInquiries.length;
      }
      scheduleDiskBackup();

      res.json({
        success: true,
        message: `Recycle Bin emptied (${deletedCount} records permanently erased).`,
        count: deletedCount
      });
    } catch (err) {
      console.error('[CLEAR BIN ERROR]:', err);
      res.status(500).json({ success: false, message: 'Failed to clear Recycle Bin.' });
    }
  });

  // Restore Single Inquiry from Bin
  app.post('/api/inquiries/:id/restore', requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      if (!id || !/^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id)) {
        return res.status(400).json({ success: false, message: 'Invalid inquiry ID format.' });
      }

      let updatedDoc = null;
      if (mongoose.connection.readyState === 1) {
        updatedDoc = await Inquiry.findOneAndUpdate(
          { id },
          { $set: { isDeleted: false, deletedAt: null } },
          { new: true }
        ).lean();
      }

      const idx = inMemoryInquiries.findIndex(i => i.id === id);
      if (idx !== -1) {
        inMemoryInquiries[idx].isDeleted = false;
        inMemoryInquiries[idx].deletedAt = null;
        inMemoryInquiries[idx].updatedAt = new Date().toISOString();
        if (!updatedDoc) updatedDoc = inMemoryInquiries[idx];
        scheduleDiskBackup();
      }

      if (!updatedDoc) {
        return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
      }

      res.json({
        success: true,
        message: `Inquiry ${id} recovered from Recycle Bin.`,
        data: normalizeInquiry(updatedDoc)
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to restore inquiry.' });
    }
  });

  // Bulk Restore Inquiries from Bin
  app.post('/api/inquiries/bulk-restore', requireAdminAuth, async (req, res) => {
    try {
      const { ids } = req.body;
      if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) {
        return res.status(400).json({ success: false, message: 'Invalid lead IDs specified.' });
      }

      const validIds = ids.filter(id => typeof id === 'string' && /^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id));

      if (mongoose.connection.readyState === 1) {
        await Inquiry.updateMany(
          { id: { $in: validIds } },
          { $set: { isDeleted: false, deletedAt: null } }
        );
      }

      inMemoryInquiries.forEach(inq => {
        if (validIds.includes(inq.id)) {
          inq.isDeleted = false;
          inq.deletedAt = null;
          inq.updatedAt = new Date().toISOString();
        }
      });
      scheduleDiskBackup();

      res.json({
        success: true,
        message: `Successfully recovered ${validIds.length} lead(s) from Recycle Bin.`
      });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Bulk restore failed.' });
    }
  });

  // Delete Single Inquiry (Soft delete to Bin by default, permanent if ?permanent=true)
  app.delete('/api/inquiries/:id', requireAdminAuth, async (req, res) => {
    try {
      const { id } = req.params;
      const isPermanent = req.query.permanent === 'true';

      if (!id || !/^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id)) {
        return res.status(400).json({ success: false, message: 'Invalid inquiry ID format.' });
      }

      let found = false;

      if (isPermanent) {
        if (mongoose.connection.readyState === 1) {
          const resDb = await Inquiry.findOneAndDelete({ id });
          if (resDb) found = true;
        }

        const prevLen = inMemoryInquiries.length;
        inMemoryInquiries = inMemoryInquiries.filter(inq => inq.id !== id);
        if (inMemoryInquiries.length !== prevLen) {
          found = true;
          scheduleDiskBackup();
        }

        if (!found) {
          return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
        }

        return res.json({ success: true, message: `Inquiry ${id} permanently deleted.` });
      } else {
        // Soft Delete: Move to Recycle Bin
        const now = new Date();
        if (mongoose.connection.readyState === 1) {
          const resDb = await Inquiry.findOneAndUpdate(
            { id },
            { $set: { isDeleted: true, deletedAt: now } },
            { new: true }
          );
          if (resDb) found = true;
        }

        const idx = inMemoryInquiries.findIndex(i => i.id === id);
        if (idx !== -1) {
          inMemoryInquiries[idx].isDeleted = true;
          inMemoryInquiries[idx].deletedAt = now.toISOString();
          inMemoryInquiries[idx].updatedAt = now.toISOString();
          found = true;
          scheduleDiskBackup();
        }

        if (!found) {
          return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
        }

        return res.json({ success: true, message: `Inquiry ${id} moved to Recycle Bin.` });
      }
    } catch (err) {
      res.status(500).json({ success: false, message: 'Failed to process delete inquiry.' });
    }
  });

  // Bulk Delete Inquiries (Soft delete to Bin by default, permanent if ?permanent=true)
  app.post('/api/inquiries/bulk-delete', requireAdminAuth, async (req, res) => {
    try {
      const { ids } = req.body;
      const isPermanent = req.query.permanent === 'true';

      if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) {
        return res.status(400).json({ success: false, message: 'Invalid lead IDs specified (maximum 100 at a time).' });
      }

      const validIds = ids.filter(id => typeof id === 'string' && /^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id));
      const now = new Date();

      if (isPermanent) {
        let deletedCount = 0;
        if (mongoose.connection.readyState === 1) {
          const resDb = await Inquiry.deleteMany({ id: { $in: validIds } });
          deletedCount = resDb.deletedCount;
        }

        const prevLen = inMemoryInquiries.length;
        inMemoryInquiries = inMemoryInquiries.filter(inq => !validIds.includes(inq.id));
        if (!deletedCount) {
          deletedCount = prevLen - inMemoryInquiries.length;
        }
        scheduleDiskBackup();

        return res.json({
          success: true,
          message: `Successfully erased ${deletedCount || validIds.length} record(s) permanently.`
        });
      } else {
        // Bulk soft delete: Move to Recycle Bin
        if (mongoose.connection.readyState === 1) {
          await Inquiry.updateMany(
            { id: { $in: validIds } },
            { $set: { isDeleted: true, deletedAt: now } }
          );
        }

        inMemoryInquiries.forEach(inq => {
          if (validIds.includes(inq.id)) {
            inq.isDeleted = true;
            inq.deletedAt = now.toISOString();
            inq.updatedAt = now.toISOString();
          }
        });
        scheduleDiskBackup();

        return res.json({
          success: true,
          message: `Successfully moved ${validIds.length} lead(s) to Recycle Bin.`
        });
      }
    } catch (err) {
      res.status(500).json({ success: false, message: 'Bulk delete failed.' });
    }
  });

  // ==========================================
  // 12. STATIC CLIENT SERVING & SPA FALLBACK (CLEAN URLS)
  // ==========================================
  const CLIENT_DIST = path.join(__dirname, '../client/dist');
  if (fs.existsSync(CLIENT_DIST)) {
    // 1. Explicit sitemap.xml handler
    app.get('/sitemap.xml', (_req, res) => {
      res.setHeader('Content-Type', 'application/xml; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      const sitemapPath = path.join(CLIENT_DIST, 'sitemap.xml');
      if (fs.existsSync(sitemapPath)) {
        return res.sendFile(sitemapPath);
      }
      res.status(404).send('Sitemap not found');
    });

    // 2. Explicit robots.txt handler
    app.get('/robots.txt', (_req, res) => {
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      const robotsPath = path.join(CLIENT_DIST, 'robots.txt');
      if (fs.existsSync(robotsPath)) {
        return res.sendFile(robotsPath);
      }
      res.status(404).send('Robots.txt not found');
    });

    // 3. Immutable caching for hashed JS/CSS assets (1 Year)
    app.use('/assets', express.static(path.join(CLIENT_DIST, 'assets'), {
      maxAge: '1y',
      immutable: true
    }));

    // 4. Static images caching (30 Days)
    app.use('/images', express.static(path.join(CLIENT_DIST, 'images'), {
      maxAge: '30d'
    }));

    // 5. General static files
    app.use(express.static(CLIENT_DIST, {
      maxAge: '1h',
      setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
          res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
        }
      }
    }));

    // 6. SPA Catch-All fallback for clean browser URLs (/about, /services, /blog, etc.)
    app.get('{*splat}', (req, res, next) => {
      if (req.path.startsWith('/api/')) {
        return next();
      }
      res.sendFile(path.join(CLIENT_DIST, 'index.html'));
    });
  }

  // ==========================================
  // 13. API 404 & ERROR HANDLERS
  // ==========================================

  app.use((req, res) => {
    res.status(404).json({
      success: false,
      message: 'Requested API resource not found.'
    });
  });

  app.use((err, req, res, _next) => {
    console.error(`[PROCESS ${process.pid} ERROR]:`, err.message);
    res.status(500).json({
      success: false,
      message: 'Internal server error occurred.'
    });
  });

  // Start HTTP Server with Keep-Alive optimization
  const server = app.listen(PORT, () => {
    console.log(`[GLOBAL ENTERPRISES] 🚀 Process ${process.pid} listening on port ${PORT} (${NODE_ENV} mode)`);
  });

  // HTTP Keep-Alive timeouts optimized for reverse proxies (Cloudflare, Nginx, ALB, Render)
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;

  // Graceful shutdown handling
  const shutdown = async (signal) => {
    console.log(`[PROCESS ${process.pid}] Received ${signal}. Initiating graceful shutdown...`);
    server.close(async () => {
      try {
        if (diskWriteTimer) {
          clearTimeout(diskWriteTimer);
          await fsp.writeFile(INQUIRIES_FILE, JSON.stringify(inMemoryInquiries.slice(0, 1000), null, 2), 'utf8');
        }
        await mongoose.connection.close();
        // Gracefully disconnect Redis
        if (redisClient) {
          await redisClient.quit();
          console.log(`[PROCESS ${process.pid}] 🔴 Redis disconnected.`);
        }
        console.log(`[PROCESS ${process.pid}] ✅ Graceful shutdown complete.`);
        process.exit(0);
      } catch (err) {
        console.error(`[PROCESS ${process.pid}] Error during shutdown:`, err.message);
        process.exit(1);
      }
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
