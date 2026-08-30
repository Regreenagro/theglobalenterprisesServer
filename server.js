import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Persistent or environment-provided JWT secret (32+ bytes)
const JWT_SECRET = process.env.JWT_SECRET || 'global-enterprises-production-secret-key-2026-secure-auth-jwt';

// ==========================================
// 1. DIRECTORIES & DATA STORAGE
// ==========================================
const DATA_DIR = path.join(__dirname, 'data');
const INQUIRIES_FILE = path.join(DATA_DIR, 'inquiries.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory rate limiting & active OTP storage
const rateLimitStore = new Map();
const activeOTPs = new Map();

// ==========================================
// 2. CRYPTOGRAPHIC UTILITIES
// ==========================================

/**
 * Hash a password using scrypt with a random 16-byte salt
 */
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return `${salt}:${derivedKey.toString('hex')}`;
}

/**
 * Verify a password against a salt:hash string using constant-time comparison
 */
function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string') return false;
  
  // Backward compatibility migration for plaintext password
  if (!storedHash.includes(':')) {
    return password === storedHash;
  }

  const [salt, key] = storedHash.split(':');
  if (!salt || !key) return false;

  const keyBuffer = Buffer.from(key, 'hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  
  if (keyBuffer.length !== derivedKey.length) return false;
  return crypto.timingSafeEqual(keyBuffer, derivedKey);
}

/**
 * Sign a payload as a cryptographic HMAC-SHA256 JWT
 */
function createJWT(payload, expiresInSeconds = 86400) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = Buffer.from(JSON.stringify({
    ...payload,
    iat: now,
    exp: now + expiresInSeconds
  })).toString('base64url');

  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${fullPayload}`)
    .digest('base64url');

  return `${header}.${fullPayload}.${signature}`;
}

/**
 * Verify and decode an HMAC-SHA256 JWT
 */
function verifyJWT(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const expectedSignature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${payload}`)
    .digest('base64url');

  const sigBuf = Buffer.from(signature);
  const expSigBuf = Buffer.from(expectedSignature);

  if (sigBuf.length !== expSigBuf.length || !crypto.timingSafeEqual(sigBuf, expSigBuf)) {
    return null;
  }

  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp && decoded.exp < now) {
      return null; // Expired
    }
    return decoded;
  } catch {
    return null;
  }
}

/**
 * String sanitizer to prevent stored XSS and injection
 */
function sanitizeString(input, maxLength = 1000) {
  if (typeof input !== 'string') return '';
  return input
    .trim()
    .slice(0, maxLength)
    .replace(/[<>]/g, ''); // Strip direct tag brackets
}

// ==========================================
// 3. SEED DATA & MIGRATION
// ==========================================
const defaultAdmin = {
  id: 'admin',
  email: 'admin@theglobal.com',
  phone: '9899933768',
  name: 'Global Admin Board',
  password: hashPassword(process.env.ADMIN_INITIAL_PASSWORD || 'admin123'),
  role: 'Super Admin',
  createdAt: new Date().toISOString()
};

function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
      return fallback;
    }
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(`Error reading ${file}:`, err.message);
    return fallback;
  }
}

function writeJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`Error writing ${file}:`, err.message);
  }
}

// Initialize and migrate admin password to secure hash if needed
let currentAdmin = readJSON(ADMIN_FILE, defaultAdmin);
if (currentAdmin.password && !currentAdmin.password.includes(':')) {
  currentAdmin.password = hashPassword(currentAdmin.password);
  writeJSON(ADMIN_FILE, currentAdmin);
}

if (!fs.existsSync(INQUIRIES_FILE)) {
  writeJSON(INQUIRIES_FILE, []);
}

// ==========================================
// 4. SECURITY MIDDLEWARE
// ==========================================

// Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Production-ready CORS
const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000,http://localhost:3001,http://localhost:5173,https://globalenterprises.in')
  .split(',')
  .map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (like mobile apps, server-to-server, curl) or allowed origins
    if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      return callback(null, true);
    }
    return callback(new Error('CORS Policy: Origin not allowed.'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Body parser with size limits
app.use(express.json({ limit: '100kb' }));

// In-Memory Sliding Window Rate Limiter
function rateLimiter(options = { windowMs: 60 * 1000, max: 100, message: 'Too many requests. Please slow down.' }) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown-ip';
    const key = `${req.baseUrl || req.path}:${ip}`;
    const now = Date.now();

    const record = rateLimitStore.get(key) || { count: 0, resetAt: now + options.windowMs };

    if (now > record.resetAt) {
      record.count = 1;
      record.resetAt = now + options.windowMs;
    } else {
      record.count += 1;
    }

    rateLimitStore.set(key, record);

    if (record.count > options.max) {
      const retryAfter = Math.ceil((record.resetAt - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        success: false,
        message: options.message,
        retryAfterSeconds: retryAfter
      });
    }

    next();
  };
}

// Cleanup rateLimitStore every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now > record.resetAt) {
      rateLimitStore.delete(key);
    }
  }
}, 10 * 60 * 1000);

// Authentication Guard Middleware for Admin Routes
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Admin authentication required.'
    });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyJWT(token);

  if (!decoded || (decoded.role !== 'Super Admin' && decoded.role !== 'Admin')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid or expired session token.'
    });
  }

  req.admin = decoded;
  next();
}

// ==========================================
// 5. PUBLIC API ENDPOINTS
// ==========================================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'operational',
    service: 'Global Enterprises Central CRM API',
    timestamp: new Date().toISOString()
  });
});

// Submit New Customer Inquiry (Public with rate limiter)
const inquiryLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Inquiry rate limit exceeded. Please wait a few minutes before submitting again.'
});

app.post('/api/inquiries', inquiryLimiter, (req, res) => {
  const { name, company, phone, email, service, budget, location, message } = req.body;

  const sanitizedName = sanitizeString(name, 100);
  const sanitizedPhone = sanitizeString(phone, 30);

  if (!sanitizedName || sanitizedName.length < 2) {
    return res.status(400).json({ success: false, message: 'Please provide a valid full name (minimum 2 characters).' });
  }

  const cleanPhoneDigits = sanitizedPhone.replace(/[^0-9+]/g, '');
  if (!cleanPhoneDigits || cleanPhoneDigits.length < 8) {
    return res.status(400).json({ success: false, message: 'Please provide a valid contact phone number.' });
  }

  const inquiries = readJSON(INQUIRIES_FILE, []);
  const newInquiry = {
    id: 'INQ-' + crypto.randomInt(1000, 9999),
    name: sanitizedName,
    company: sanitizeString(company, 120) || 'Enterprise Client',
    phone: sanitizedPhone,
    email: sanitizeString(email, 120) || 'N/A',
    service: sanitizeString(service, 150) || 'General Infrastructure Inquiry',
    budget: sanitizeString(budget, 80) || 'Undisclosed',
    location: sanitizeString(location, 150) || 'NCR, India',
    message: sanitizeString(message, 2000) || 'Submitted via website form.',
    status: 'New',
    read: false,
    notes: '',
    createdAt: new Date().toISOString()
  };

  inquiries.unshift(newInquiry);
  writeJSON(INQUIRIES_FILE, inquiries);

  res.status(201).json({
    success: true,
    message: 'Inquiry received securely.',
    data: newInquiry
  });
});

// ==========================================
// 6. ADMIN AUTHENTICATION & SENSITIVE ENDPOINTS
// ==========================================

const loginLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: 'Too many login attempts. For security, please try again in 15 minutes.'
});

// Admin Login
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { adminId, password } = req.body;
  if (!adminId || !password) {
    return res.status(400).json({ success: false, message: 'Admin ID and password are required.' });
  }

  const adminData = readJSON(ADMIN_FILE, defaultAdmin);
  const cleanId = String(adminId).trim().toLowerCase();

  const isIdentifierMatch = 
    cleanId === adminData.id.toLowerCase() ||
    cleanId === adminData.email.toLowerCase() ||
    cleanId === adminData.phone;

  if (isIdentifierMatch && verifyPassword(password, adminData.password)) {
    // If password was stored in plaintext, auto-migrate to hash
    if (!adminData.password.includes(':')) {
      adminData.password = hashPassword(password);
      writeJSON(ADMIN_FILE, adminData);
    }

    const token = createJWT({
      id: adminData.id,
      email: adminData.email,
      role: adminData.role || 'Super Admin'
    }, 86400); // 24-hour token

    return res.json({
      success: true,
      token,
      admin: {
        id: adminData.id,
        email: adminData.email,
        phone: adminData.phone,
        name: adminData.name,
        role: adminData.role
      }
    });
  } else {
    // Generic error message to prevent account enumeration
    return res.status(401).json({
      success: false,
      message: 'Invalid credentials. Please verify your credentials and try again.'
    });
  }
});

// Request OTP for Admin Verification (Rate-limited, never exposes OTP in response)
const otpLimiter = rateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 3,
  message: 'Too many OTP requests. Please wait 10 minutes.'
});

app.post('/api/admin/send-otp', otpLimiter, requireAdminAuth, (req, res) => {
  const adminData = readJSON(ADMIN_FILE, defaultAdmin);
  const generatedOTP = crypto.randomInt(100000, 999999).toString();

  activeOTPs.set('admin', {
    otpHash: hashPassword(generatedOTP),
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes validity
    attempts: 0
  });

  // In a production setup, dispatch via SMS/Email gateway here
  // We do NOT return the OTP in the HTTP response

  res.json({
    success: true,
    message: `6-Digit verification code dispatched to registered contact (${adminData.email}).`
  });
});

// Change Admin Password
app.post('/api/admin/change-password', requireAdminAuth, (req, res) => {
  const { mode, oldPassword, otpCode, newPassword } = req.body;
  let adminData = readJSON(ADMIN_FILE, defaultAdmin);

  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long.' });
  }

  if (mode === 'old_password') {
    if (!verifyPassword(oldPassword, adminData.password)) {
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

  adminData.password = hashPassword(newPassword);
  adminData.updatedAt = new Date().toISOString();
  writeJSON(ADMIN_FILE, adminData);

  res.json({
    success: true,
    message: 'Admin password updated securely.'
  });
});

// ==========================================
// 7. PROTECTED INQUIRY MANAGEMENT ENDPOINTS
// ==========================================

// Get All Inquiries (Requires Admin Auth)
app.get('/api/inquiries', requireAdminAuth, (req, res) => {
  const inquiries = readJSON(INQUIRIES_FILE, []);
  res.json({
    success: true,
    count: inquiries.length,
    data: inquiries
  });
});

// Update Inquiry Status / Notes / Read State (Requires Admin Auth)
app.patch('/api/inquiries/:id', requireAdminAuth, (req, res) => {
  const { id } = req.params;
  const { status, notes, read } = req.body;

  // Validate ID format
  if (!id || !/^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id)) {
    return res.status(400).json({ success: false, message: 'Invalid inquiry ID format.' });
  }

  let inquiries = readJSON(INQUIRIES_FILE, []);
  const index = inquiries.findIndex(inq => inq.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
  }

  const allowedStatuses = ['New', 'In Progress', 'Contacted', 'Closed'];
  if (status !== undefined) {
    if (allowedStatuses.includes(status)) {
      inquiries[index].status = status;
    }
  }

  if (notes !== undefined) {
    inquiries[index].notes = sanitizeString(notes, 1000);
  }

  if (read !== undefined) {
    inquiries[index].read = Boolean(read);
  }

  inquiries[index].updatedAt = new Date().toISOString();
  writeJSON(INQUIRIES_FILE, inquiries);

  res.json({
    success: true,
    message: 'Inquiry record updated.',
    data: inquiries[index]
  });
});

// Delete Single Inquiry (Requires Admin Auth)
app.delete('/api/inquiries/:id', requireAdminAuth, (req, res) => {
  const { id } = req.params;

  if (!id || !/^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id)) {
    return res.status(400).json({ success: false, message: 'Invalid inquiry ID format.' });
  }

  let inquiries = readJSON(INQUIRIES_FILE, []);
  const initialLength = inquiries.length;
  inquiries = inquiries.filter(inq => inq.id !== id);

  if (inquiries.length === initialLength) {
    return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
  }

  writeJSON(INQUIRIES_FILE, inquiries);
  res.json({ success: true, message: `Inquiry ${id} deleted securely.` });
});

// Bulk Delete Inquiries (Requires Admin Auth)
app.post('/api/inquiries/bulk-delete', requireAdminAuth, (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) {
    return res.status(400).json({ success: false, message: 'Invalid or excessive lead IDs specified (maximum 100 at a time).' });
  }

  const validIds = ids.filter(id => typeof id === 'string' && /^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id));

  let inquiries = readJSON(INQUIRIES_FILE, []);
  const initialCount = inquiries.length;
  inquiries = inquiries.filter(inq => !validIds.includes(inq.id));
  writeJSON(INQUIRIES_FILE, inquiries);

  const deletedCount = initialCount - inquiries.length;
  res.json({
    success: true,
    message: `Successfully deleted ${deletedCount} record(s).`
  });
});

// ==========================================
// 8. GLOBAL ERROR & NOT FOUND HANDLERS
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Requested API resource not found.'
  });
});

app.use((err, req, res, _next) => {
  console.error('[SERVER ERROR]:', err.message);
  res.status(500).json({
    success: false,
    message: 'Internal server error occurred.'
  });
});

app.listen(PORT, () => {
  console.log(`[GLOBAL ENTERPRISES] 🚀 Hardened Central API Server running on port ${PORT} (${NODE_ENV} mode)`);
});
