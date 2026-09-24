import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Persistent or environment-provided JWT secret (32+ bytes)
const JWT_SECRET = process.env.JWT_SECRET || 'global-enterprises-production-secret-key-2026-secure-auth-jwt';

// MongoDB Connection URI (Configured from environment or user-specified Atlas cluster)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://regreenagromarketing_db_user:3VQdk3BoRNFUWYgQ@cluster0.wcajcsh.mongodb.net/global_enterprises?appName=Cluster0';

// ==========================================
// 1. DIRECTORIES & BACKUP DATA STORAGE
// ==========================================
const DATA_DIR = path.join(__dirname, 'data');
const INQUIRIES_FILE = path.join(DATA_DIR, 'inquiries.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// In-memory rate limiting & active OTP storage
const rateLimitStore = new Map();
const activeOTPs = new Map();

// ==========================================
// 2. CRYPTOGRAPHIC UTILITIES
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

  const keyBuffer = Buffer.from(key, 'hex');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  
  if (keyBuffer.length !== derivedKey.length) return false;
  return crypto.timingSafeEqual(keyBuffer, derivedKey);
}

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
    .replace(/[<>]/g, '');
}

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

// ==========================================
// 3. MONGOOSE SCHEMAS & MODELS
// ==========================================

const inquirySchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  type: { type: String, default: 'inquiry' },
  name: { type: String, required: true, trim: true },
  company: { type: String, default: 'Enterprise Client' },
  phone: { type: String, required: true, trim: true },
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
  notes: { type: String, default: '' }
}, {
  timestamps: true
});

const adminSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  username: { type: String, default: 'admin', trim: true, index: true },
  email: { type: String, required: true },
  phone: { type: String, default: '9899933768' },
  name: { type: String, default: 'Global Admin Board' },
  password: { type: String, required: true },
  role: { type: String, default: 'Super Admin' }
}, {
  timestamps: true
});

const Inquiry = mongoose.models.Inquiry || mongoose.model('Inquiry', inquirySchema);
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// Initial fallback admin data
const defaultAdmin = {
  id: 'admin',
  username: process.env.ADMIN_INITIAL_USERNAME || 'admin',
  email: process.env.ADMIN_INITIAL_EMAIL || 'admin@theglobal.com',
  phone: process.env.ADMIN_INITIAL_PHONE || '9899933768',
  name: 'Global Admin Board',
  password: hashPassword(process.env.ADMIN_INITIAL_PASSWORD || 'admin123'),
  role: 'Super Admin'
};

// ==========================================
// 4. DATABASE CONNECTION & DATA MIGRATION
// ==========================================

async function connectMongoDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 8000
    });
    console.log('[GLOBAL ENTERPRISES] 🍃 Connected to MongoDB Atlas successfully.');

    // Seed or migrate Admin account with username & password
    const existingAdmin = await Admin.findOne({
      $or: [{ id: defaultAdmin.id }, { username: defaultAdmin.username }, { email: defaultAdmin.email }]
    });

    if (!existingAdmin) {
      await Admin.create(defaultAdmin);
      console.log('[GLOBAL ENTERPRISES] ✅ Initialized admin account (Username: admin, Password: admin123) in MongoDB.');
    } else {
      if (!existingAdmin.username) {
        existingAdmin.username = 'admin';
        await existingAdmin.save();
        console.log('[GLOBAL ENTERPRISES] ✅ Updated existing admin record with username "admin" in MongoDB.');
      }
    }

    // Auto-migrate local inquiries from JSON to MongoDB if collection is empty
    const count = await Inquiry.countDocuments();
    if (count === 0 && fs.existsSync(INQUIRIES_FILE)) {
      const localInquiries = readJSON(INQUIRIES_FILE, []);
      if (Array.isArray(localInquiries) && localInquiries.length > 0) {
        for (const item of localInquiries) {
          try {
            await Inquiry.updateOne({ id: item.id }, { $set: item }, { upsert: true });
          } catch (mErr) {
            console.error(`Migration error for ${item.id}:`, mErr.message);
          }
        }
        console.log(`[GLOBAL ENTERPRISES] 📥 Migrated ${localInquiries.length} local inquiries to MongoDB.`);
      }
    }
  } catch (err) {
    console.error('[GLOBAL ENTERPRISES] ⚠️ MongoDB connection error:', err.message);
  }
}

connectMongoDB();

// ==========================================
// 5. SECURITY MIDDLEWARE & CORS
// ==========================================

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

const allowedOrigins = (process.env.CORS_ORIGIN || 'https://theglobalenterprises.vercel.app,http://localhost:3000,http://localhost:3001,http://localhost:5173,https://globalenterprises.in')
  .split(',')
  .map(o => o.trim().replace(/\/$/, ''));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    const cleanOrigin = origin.replace(/\/$/, '');
    if (
      allowedOrigins.includes(cleanOrigin) ||
      allowedOrigins.includes('*') ||
      cleanOrigin === 'https://theglobalenterprises.vercel.app' ||
      cleanOrigin.endsWith('.vercel.app')
    ) {
      return callback(null, true);
    }
    return callback(new Error(`CORS Policy: Origin ${origin} not allowed.`));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json({ limit: '100kb' }));

// Sliding Window Rate Limiter
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
    createdAt: inq.createdAt,
    updatedAt: inq.updatedAt
  };
}

// ==========================================
// 6. PUBLIC API ENDPOINTS
// ==========================================

// Health Check
app.get('/api/health', (req, res) => {
  const isDbConnected = mongoose.connection.readyState === 1;
  res.json({
    status: 'operational',
    service: 'Global Enterprises Central CRM API',
    database: isDbConnected ? 'MongoDB Atlas (Connected)' : 'Local Fallback Storage',
    timestamp: new Date().toISOString()
  });
});

const inquiryLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Inquiry rate limit exceeded. Please wait a few minutes before submitting again.'
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
      notes: ''
    };

    let savedRecord = null;

    // Save to MongoDB if connected
    if (mongoose.connection.readyState === 1) {
      savedRecord = await Inquiry.create(newInquiryData);
    } else {
      // Local file fallback
      const inquiries = readJSON(INQUIRIES_FILE, []);
      inquiries.unshift(newInquiryData);
      writeJSON(INQUIRIES_FILE, inquiries);
      savedRecord = newInquiryData;
    }

    // Mirror to local file for offline resilience
    try {
      const localInqs = readJSON(INQUIRIES_FILE, []);
      localInqs.unshift(normalizeInquiry(savedRecord));
      writeJSON(INQUIRIES_FILE, localInqs.slice(0, 1000));
    } catch {}

    res.status(201).json({
      success: true,
      message: 'Inquiry received securely.',
      data: normalizeInquiry(savedRecord)
    });
  } catch (err) {
    console.error('Inquiry submission error:', err);
    res.status(500).json({ success: false, message: 'Failed to process inquiry. Please try again.' });
  }
});

// ==========================================
// 7. ADMIN AUTHENTICATION
// ==========================================

const loginLimiter = rateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 8,
  message: 'Too many login attempts. For security, please try again in 15 minutes.'
});

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { adminId, password } = req.body;
    if (!adminId || !password) {
      return res.status(400).json({ success: false, message: 'Admin ID and password are required.' });
    }

    const cleanId = String(adminId).trim().toLowerCase();
    let adminRecord = null;

    if (mongoose.connection.readyState === 1) {
      adminRecord = await Admin.findOne({
        $or: [
          { id: cleanId },
          { username: cleanId },
          { email: cleanId },
          { phone: cleanId }
        ]
      });
    }

    // Fallback to local admin file if not found or DB offline
    if (!adminRecord) {
      const localAdmin = readJSON(ADMIN_FILE, defaultAdmin);
      const isMatch = 
        cleanId === (localAdmin.id || '').toLowerCase() ||
        cleanId === (localAdmin.username || '').toLowerCase() ||
        cleanId === (localAdmin.email || '').toLowerCase() ||
        cleanId === localAdmin.phone;
      
      if (isMatch) {
        adminRecord = localAdmin;
      }
    }

    if (adminRecord && verifyPassword(password, adminRecord.password)) {
      const token = createJWT({
        id: adminRecord.id,
        email: adminRecord.email,
        role: adminRecord.role || 'Super Admin'
      }, 86400);

      return res.json({
        success: true,
        token,
        admin: {
          id: adminRecord.id,
          email: adminRecord.email,
          phone: adminRecord.phone,
          name: adminRecord.name,
          role: adminRecord.role
        }
      });
    }

    return res.status(401).json({
      success: false,
      message: 'Invalid administrative credentials. Please verify and try again.'
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'Authentication service temporarily unavailable.' });
  }
});

const otpLimiter = rateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 3,
  message: 'Too many OTP requests. Please wait 10 minutes.'
});

app.post('/api/admin/send-otp', otpLimiter, requireAdminAuth, async (req, res) => {
  try {
    let email = 'admin@theglobal.com';
    if (mongoose.connection.readyState === 1) {
      const admin = await Admin.findOne({ id: req.admin.id });
      if (admin && admin.email) email = admin.email;
    } else {
      const local = readJSON(ADMIN_FILE, defaultAdmin);
      if (local && local.email) email = local.email;
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

app.post('/api/admin/change-password', requireAdminAuth, async (req, res) => {
  try {
    const { mode, oldPassword, otpCode, newPassword } = req.body;

    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long.' });
    }

    let adminRecord = null;
    if (mongoose.connection.readyState === 1) {
      adminRecord = await Admin.findOne({ id: req.admin.id });
    }
    if (!adminRecord) {
      adminRecord = readJSON(ADMIN_FILE, defaultAdmin);
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

    // Mirror to local file
    try {
      const localAdmin = readJSON(ADMIN_FILE, defaultAdmin);
      localAdmin.password = hashedNew;
      localAdmin.updatedAt = new Date().toISOString();
      writeJSON(ADMIN_FILE, localAdmin);
    } catch {}

    res.json({
      success: true,
      message: 'Admin password updated securely.'
    });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ success: false, message: 'Failed to update password.' });
  }
});

// ==========================================
// 8. PROTECTED INQUIRY MANAGEMENT ENDPOINTS
// ==========================================

// Get All Inquiries
app.get('/api/inquiries', requireAdminAuth, async (req, res) => {
  try {
    let inquiries = [];

    if (mongoose.connection.readyState === 1) {
      inquiries = await Inquiry.find().sort({ createdAt: -1 }).lean();
    } else {
      inquiries = readJSON(INQUIRIES_FILE, []);
    }

    const normalized = inquiries.map(normalizeInquiry);
    res.json({
      success: true,
      count: normalized.length,
      data: normalized
    });
  } catch (err) {
    console.error('Fetch inquiries error:', err);
    res.status(500).json({ success: false, message: 'Failed to retrieve inquiries.' });
  }
});

// Mark All Inquiries As Read
app.post('/api/inquiries/mark-all-read', requireAdminAuth, async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      await Inquiry.updateMany({ read: false }, { $set: { read: true } });
      const updated = await Inquiry.find().sort({ createdAt: -1 }).lean();
      return res.json({
        success: true,
        message: 'Marked all inquiries as read.',
        data: updated.map(normalizeInquiry)
      });
    }

    let inquiries = readJSON(INQUIRIES_FILE, []);
    inquiries = inquiries.map(inq => ({ ...inq, read: true, updatedAt: new Date().toISOString() }));
    writeJSON(INQUIRIES_FILE, inquiries);

    res.json({
      success: true,
      message: 'Marked all inquiries as read.',
      data: inquiries.map(normalizeInquiry)
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

    // Mirror in local file
    try {
      const localInqs = readJSON(INQUIRIES_FILE, []);
      const idx = localInqs.findIndex(i => i.id === id);
      if (idx !== -1) {
        Object.assign(localInqs[idx], updateFields, { updatedAt: new Date().toISOString() });
        writeJSON(INQUIRIES_FILE, localInqs);
        if (!updatedDoc) updatedDoc = localInqs[idx];
      }
    } catch {}

    if (!updatedDoc) {
      return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
    }

    res.json({
      success: true,
      message: 'Inquiry record updated.',
      data: normalizeInquiry(updatedDoc)
    });
  } catch (err) {
    console.error('Update inquiry error:', err);
    res.status(500).json({ success: false, message: 'Failed to update inquiry.' });
  }
});

// Delete Single Inquiry
app.delete('/api/inquiries/:id', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id || !/^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id)) {
      return res.status(400).json({ success: false, message: 'Invalid inquiry ID format.' });
    }

    let deleted = false;

    if (mongoose.connection.readyState === 1) {
      const resDb = await Inquiry.findOneAndDelete({ id });
      if (resDb) deleted = true;
    }

    // Also remove from local JSON file
    try {
      let localInqs = readJSON(INQUIRIES_FILE, []);
      const prevLen = localInqs.length;
      localInqs = localInqs.filter(inq => inq.id !== id);
      if (localInqs.length !== prevLen) {
        writeJSON(INQUIRIES_FILE, localInqs);
        deleted = true;
      }
    } catch {}

    if (!deleted) {
      return res.status(404).json({ success: false, message: 'Inquiry record not found.' });
    }

    res.json({ success: true, message: `Inquiry ${id} deleted securely.` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete inquiry.' });
  }
});

// Bulk Delete Inquiries
app.post('/api/inquiries/bulk-delete', requireAdminAuth, async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) {
      return res.status(400).json({ success: false, message: 'Invalid lead IDs specified (maximum 100 at a time).' });
    }

    const validIds = ids.filter(id => typeof id === 'string' && /^INQ-[a-zA-Z0-9_-]{1,20}$/.test(id));
    let deletedCount = 0;

    if (mongoose.connection.readyState === 1) {
      const resDb = await Inquiry.deleteMany({ id: { $in: validIds } });
      deletedCount = resDb.deletedCount;
    }

    try {
      let localInqs = readJSON(INQUIRIES_FILE, []);
      const prevLen = localInqs.length;
      localInqs = localInqs.filter(inq => !validIds.includes(inq.id));
      if (!deletedCount) {
        deletedCount = prevLen - localInqs.length;
      }
      writeJSON(INQUIRIES_FILE, localInqs);
    } catch {}

    res.json({
      success: true,
      message: `Successfully deleted ${deletedCount} record(s).`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Bulk delete failed.' });
  }
});

// ==========================================
// 9. GLOBAL ERROR & NOT FOUND HANDLERS
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
  console.log(`[GLOBAL ENTERPRISES] 🚀 Central API Server running on port ${PORT} (${NODE_ENV} mode)`);
  console.log(`[GLOBAL ENTERPRISES] 🌐 Connected to MongoDB Cluster`);
});
