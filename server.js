import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const DATA_DIR = path.join(__dirname, 'data');
const INQUIRIES_FILE = path.join(DATA_DIR, 'inquiries.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initial Admin Credentials
const defaultAdmin = {
  id: 'admin',
  email: 'admin@theglobal.com',
  phone: '9899933768',
  name: 'Global Admin Board',
  password: 'admin123',
  role: 'Super Admin'
};

// Seed Demo Customer Account
const defaultUsers = [
  {
    id: 'USR-7001',
    name: 'Amit Patel',
    email: 'amit.patel@gmail.com',
    phone: '9811223344',
    password: 'user123',
    cart: [
      {
        id: 'prod-cctv-4k',
        title: '4K AI Starlight CCTV Dome Camera',
        price: 18500,
        image: '/images/cctv.jpg',
        quantity: 2
      }
    ],
    wishlist: [
      {
        id: 'prod-speedgate-opt',
        title: 'Biometric Optical Speed Gate Barrier',
        price: 125000,
        image: '/images/speedgates.jpg'
      }
    ],
    createdAt: new Date().toISOString()
  }
];

// Memory store for OTPs
const activeOTPs = {};

// Helper to read data
function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
      return fallback;
    }
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(`Error reading ${file}:`, err);
    return fallback;
  }
}

// Helper to write data
function writeJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`Error writing ${file}:`, err);
  }
}

// Initialize seed data
readJSON(ADMIN_FILE, defaultAdmin);
readJSON(USERS_FILE, defaultUsers);
if (!fs.existsSync(INQUIRIES_FILE)) {
  writeJSON(INQUIRIES_FILE, []);
}

// ================= ADMIN API ENDPOINTS =================

// 1. Admin Authentication / Login
app.post('/api/admin/login', (req, res) => {
  const { adminId, password } = req.body;
  const adminData = readJSON(ADMIN_FILE, defaultAdmin);

  if ((adminId === adminData.id || adminId === adminData.email || adminId === adminData.phone) && password === adminData.password) {
    const token = 'JWT-GLOBAL-ADMIN-' + Date.now();
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
    return res.status(401).json({
      success: false,
      message: 'Invalid Admin ID/Email/Phone or Password.'
    });
  }
});

// 2. Request OTP for Password Reset / Change
app.post('/api/admin/send-otp', (req, res) => {
  const { destination } = req.body;
  const adminData = readJSON(ADMIN_FILE, defaultAdmin);

  const generatedOTP = Math.floor(100000 + Math.random() * 900000).toString();
  activeOTPs['admin'] = {
    otp: generatedOTP,
    expiresAt: Date.now() + 5 * 60 * 1000
  };

  console.log(`[SECURITY OTP] 🔑 OTP Generated for Admin (${destination || adminData.email}): ${generatedOTP}`);

  res.json({
    success: true,
    message: `6-Digit OTP generated and dispatched to ${destination || adminData.email}`,
    otpDemo: generatedOTP
  });
});

// 3. Change Admin Password (Old Password OR OTP Verification)
app.post('/api/admin/change-password', (req, res) => {
  const { mode, oldPassword, otpCode, newPassword } = req.body;
  let adminData = readJSON(ADMIN_FILE, defaultAdmin);

  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ success: false, message: 'New password must be at least 4 characters long.' });
  }

  if (mode === 'old_password') {
    if (oldPassword !== adminData.password) {
      return res.status(400).json({ success: false, message: 'Incorrect Current Old Password.' });
    }
  } else if (mode === 'otp') {
    const storedOTP = activeOTPs['admin'];
    if (!storedOTP || storedOTP.otp !== otpCode || Date.now() > storedOTP.expiresAt) {
      return res.status(400).json({ success: false, message: 'Invalid or Expired 6-Digit OTP Code.' });
    }
    delete activeOTPs['admin'];
  } else {
    return res.status(400).json({ success: false, message: 'Invalid verification mode specified.' });
  }

  adminData.password = newPassword;
  adminData.updatedAt = new Date().toISOString();
  writeJSON(ADMIN_FILE, adminData);

  res.json({
    success: true,
    message: 'Admin Password updated successfully!'
  });
});

// 4. Get All Dynamic Inquiries
app.get('/api/inquiries', (req, res) => {
  let inquiries = readJSON(INQUIRIES_FILE, []);
  const dynamicInquiries = inquiries.filter(inq => !['INQ-1001', 'INQ-1002', 'INQ-1003'].includes(inq.id));
  if (dynamicInquiries.length !== inquiries.length) {
    writeJSON(INQUIRIES_FILE, dynamicInquiries);
  }
  res.json({ success: true, count: dynamicInquiries.length, data: dynamicInquiries });
});

// 5. Submit New Dynamic Inquiry
app.post('/api/inquiries', (req, res) => {
  const { name, company, phone, email, service, budget, location, message } = req.body;

  if (!name || !phone) {
    return res.status(400).json({ success: false, message: 'Name and Phone number are required' });
  }

  const inquiries = readJSON(INQUIRIES_FILE, []);
  const newInquiry = {
    id: 'INQ-' + Math.floor(1000 + Math.random() * 9000),
    name,
    company: company || 'Enterprise Client',
    phone,
    email: email || 'N/A',
    service: service || 'General Infrastructure Inquiry',
    budget: budget || 'Undisclosed',
    location: location || 'NCR, India',
    message: message || 'Submitted via website form.',
    status: 'New',
    read: false,
    notes: '',
    createdAt: new Date().toISOString()
  };

  inquiries.unshift(newInquiry);
  writeJSON(INQUIRIES_FILE, inquiries);

  res.status(201).json({
    success: true,
    message: 'Inquiry submitted successfully to Central CRM Backend',
    data: newInquiry
  });
});

// 6. Delete Selected Multiple Inquiries (Bulk Delete)
app.post('/api/inquiries/bulk-delete', (req, res) => {
  const { ids } = req.body; // Array of inquiry IDs to delete
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ success: false, message: 'No lead IDs provided for deletion.' });
  }

  let inquiries = readJSON(INQUIRIES_FILE, []);
  const initialCount = inquiries.length;
  inquiries = inquiries.filter(inq => !ids.includes(inq.id));
  writeJSON(INQUIRIES_FILE, inquiries);

  const deletedCount = initialCount - inquiries.length;

  res.json({
    success: true,
    message: `Successfully deleted ${deletedCount} selected lead(s).`
  });
});

// 7. Update Single Inquiry Status / Notes / Read State
app.patch('/api/inquiries/:id', (req, res) => {
  const { id } = req.params;
  const { status, notes, read } = req.body;

  let inquiries = readJSON(INQUIRIES_FILE, []);
  const index = inquiries.findIndex(inq => inq.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: 'Inquiry not found' });
  }

  if (status !== undefined) inquiries[index].status = status;
  if (notes !== undefined) inquiries[index].notes = notes;
  if (read !== undefined) inquiries[index].read = read;

  writeJSON(INQUIRIES_FILE, inquiries);

  res.json({
    success: true,
    message: 'Inquiry updated successfully',
    data: inquiries[index]
  });
});

// 8. Delete Individual Inquiry
app.delete('/api/inquiries/:id', (req, res) => {
  const { id } = req.params;
  let inquiries = readJSON(INQUIRIES_FILE, []);

  inquiries = inquiries.filter(inq => inq.id !== id);
  writeJSON(INQUIRIES_FILE, inquiries);

  res.json({ success: true, message: `Inquiry ${id} deleted successfully` });
});

// ================= USER ACCOUNTS, USER-SPECIFIC CART & WISHLIST APIs =================

// User Register Endpoint
app.post('/api/users/register', (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || (!email && !phone) || !password) {
    return res.status(400).json({ success: false, message: 'Name, Phone/Email and Password are required.' });
  }

  const users = readJSON(USERS_FILE, defaultUsers);
  
  // Check if user already exists
  const existing = users.find(u => (email && u.email.toLowerCase() === email.toLowerCase()) || (phone && u.phone === phone));
  if (existing) {
    return res.status(400).json({ success: false, message: 'An account with this email/phone already exists. Please login instead.' });
  }

  const newUser = {
    id: 'USR-' + Math.floor(1000 + Math.random() * 9000),
    name,
    email: email || '',
    phone: phone || '',
    password,
    cart: [],
    wishlist: [],
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  writeJSON(USERS_FILE, users);

  console.log(`[USER AUTH] 👤 New User Registered: ${name} (${email || phone})`);

  res.status(201).json({
    success: true,
    message: 'Account created successfully!',
    user: {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      phone: newUser.phone,
      cart: newUser.cart,
      wishlist: newUser.wishlist
    }
  });
});

// User Login Endpoint
app.post('/api/users/login', (req, res) => {
  const { emailOrPhone, password } = req.body;
  const users = readJSON(USERS_FILE, defaultUsers);

  const cleanInput = (emailOrPhone || '').trim().toLowerCase();
  const user = users.find(u => 
    (u.email.toLowerCase() === cleanInput || u.phone === cleanInput || u.id.toLowerCase() === cleanInput) && 
    u.password === password
  );

  if (user) {
    console.log(`[USER AUTH] 🟢 User Logged In: ${user.name} (Cart Items: ${user.cart.length})`);
    return res.json({
      success: true,
      message: `Welcome back, ${user.name}!`,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        cart: user.cart || [],
        wishlist: user.wishlist || []
      }
    });
  } else {
    return res.status(401).json({
      success: false,
      message: 'Invalid User email/phone or password. (Demo User: amit.patel@gmail.com / user123)'
    });
  }
});

// Sync User-Specific Cart & Wishlist
app.post('/api/users/sync-data', (req, res) => {
  const { userId, cart, wishlist } = req.body;
  if (!userId) {
    return res.status(400).json({ success: false, message: 'User ID is required.' });
  }

  let users = readJSON(USERS_FILE, defaultUsers);
  const index = users.findIndex(u => u.id === userId);

  if (index !== -1) {
    if (cart !== undefined) users[index].cart = cart;
    if (wishlist !== undefined) users[index].wishlist = wishlist;
    users[index].updatedAt = new Date().toISOString();
    writeJSON(USERS_FILE, users);

    console.log(`[USER DATA SYNC] 💾 Cart & Wishlist synced for user ${users[index].name}`);
    return res.json({ success: true, message: 'User data synced successfully.' });
  } else {
    return res.status(404).json({ success: false, message: 'User account not found.' });
  }
});

app.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`🚀 DYNAMIC CENTRAL CRM & USER AUTH SERVER ON PORT ${PORT}`);
  console.log(`🔑 ADMIN LOGIN: admin / admin123`);
  console.log(`👤 DEMO USER LOGIN: amit.patel@gmail.com / user123`);
  console.log(`=================================================`);
});
