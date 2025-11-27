require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const Stripe = require('stripe');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');

// Initialize Database
const db = new Database('donations.db');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password TEXT,
    display_name TEXT NOT NULL,
    country TEXT,
    total_donated INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    notifications_enabled INTEGER DEFAULT 1,
    is_guest INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS donations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT DEFAULT 'EUR',
    payment_method TEXT,
    payment_id TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_users_total ON users(total_donated DESC);
  CREATE INDEX IF NOT EXISTS idx_donations_user ON donations(user_id);
  CREATE INDEX IF NOT EXISTS idx_users_country ON users(country);
`);

// Add country column if it doesn't exist (migration for existing db)
try {
  db.exec('ALTER TABLE users ADD COLUMN country TEXT');
} catch (e) { /* column already exists */ }

try {
  db.exec('ALTER TABLE users ADD COLUMN is_guest INTEGER DEFAULT 1');
} catch (e) { /* column already exists */ }

// Create default admin if none exists
const adminExists = db.prepare('SELECT id FROM admins LIMIT 1').get();
if (!adminExists) {
  const bcryptSync = require('bcryptjs');
  const defaultPassword = bcryptSync.hashSync('admin123', 10);
  db.prepare('INSERT INTO admins (id, username, password) VALUES (?, ?, ?)').run(uuidv4(), 'admin', defaultPassword);
  console.log('Default admin created - username: admin, password: admin123');
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Email transporter (configure with your SMTP settings)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.example.com',
  port: process.env.SMTP_PORT || 587,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Badge definitions
const BADGES = [
  { threshold: 1, name: 'Lil Baby Slay', emoji: '🐣', color: '#78909c' },
  { threshold: 10, name: 'Ate and Left No Crumbs', emoji: '💅', color: '#4caf50' },
  { threshold: 100, name: 'Main Character Energy', emoji: '✨', color: '#2196f3' },
  { threshold: 1000, name: 'Understood the Assignment', emoji: '📝', color: '#9c27b0' },
  { threshold: 10000, name: 'Goated with the Sauce', emoji: '🐐', color: '#ff9800' },
  { threshold: 100000, name: 'Absolutely Unhinged Legend', emoji: '🤯', color: '#f44336' },
  { threshold: 1000000, name: 'No Cap On God Fr Fr', emoji: '👁️', color: '#ffd700' },
  { threshold: 10000000, name: 'Certified Reality Glitch', emoji: '🌌', color: '#00ffff' }
];

function getBadge(totalDonated) {
  let badge = null;
  for (const b of BADGES) {
    if (totalDonated >= b.threshold * 100) { // amounts stored in cents
      badge = b;
    }
  }
  return badge;
}

function getAllBadges(totalDonated) {
  return BADGES.filter(b => totalDonated >= b.threshold * 100);
}

// ============ AUTH ROUTES ============

// Quick start - just nickname and optional country (guest mode)
app.post('/api/auth/quick-start', (req, res) => {
  try {
    const { nickname, country } = req.body;

    if (!nickname || nickname.trim().length < 2) {
      return res.status(400).json({ error: 'Nickname must be at least 2 characters' });
    }

    // Create guest user
    const userId = uuidv4();
    db.prepare(
      'INSERT INTO users (id, display_name, country, is_guest) VALUES (?, ?, ?, 1)'
    ).run(userId, nickname.trim(), country || null);

    // Generate token
    const token = jwt.sign({ id: userId, isGuest: true }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: userId,
        displayName: nickname.trim(),
        country: country || null,
        totalDonated: 0,
        isGuest: true
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Upgrade guest to full account
app.post('/api/auth/upgrade', authenticateToken, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if email already exists
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, req.user.id);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password and update user
    const hashedPassword = await bcrypt.hash(password, 10);
    db.prepare(
      'UPDATE users SET email = ?, password = ?, is_guest = 0 WHERE id = ?'
    ).run(email, hashedPassword, req.user.id);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    // Generate new token
    const token = jwt.sign({ id: user.id, email, isGuest: false }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        country: user.country,
        totalDonated: user.total_donated,
        isGuest: false,
        badges: getAllBadges(user.total_donated)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login (for registered users)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user || user.is_guest) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, isGuest: false }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        country: user.country,
        totalDonated: user.total_donated,
        isGuest: false,
        badges: getAllBadges(user.total_donated)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    country: user.country,
    totalDonated: user.total_donated,
    isGuest: user.is_guest === 1,
    badges: getAllBadges(user.total_donated),
    rank: getUserRank(user.id)
  });
});

// ============ PAYMENT ROUTES ============

// Create Stripe Payment Intent
app.post('/api/payments/create-intent', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body; // amount in EUR (e.g., 10 for 10 EUR)

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const amountInCents = Math.round(amount * 100);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: 'eur',
      automatic_payment_methods: {
        enabled: true,
      },
      metadata: {
        userId: req.user.id
      }
    });

    // Create pending donation record
    const donationId = uuidv4();
    db.prepare(
      'INSERT INTO donations (id, user_id, amount, payment_id, status) VALUES (?, ?, ?, ?, ?)'
    ).run(donationId, req.user.id, amountInCents, paymentIntent.id, 'pending');

    res.json({
      clientSecret: paymentIntent.client_secret,
      donationId
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Payment initialization failed' });
  }
});

// Confirm payment (webhook alternative for testing)
app.post('/api/payments/confirm', authenticateToken, async (req, res) => {
  try {
    const { paymentIntentId } = req.body;

    // Verify payment with Stripe
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status !== 'succeeded') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    // Update donation status
    const donation = db.prepare(
      'SELECT * FROM donations WHERE payment_id = ? AND user_id = ?'
    ).get(paymentIntentId, req.user.id);

    if (!donation || donation.status === 'completed') {
      return res.status(400).json({ error: 'Invalid donation' });
    }

    // Get user's current rank before update
    const rankBefore = getUserRank(req.user.id);

    // Update donation and user total
    db.prepare('UPDATE donations SET status = ? WHERE id = ?').run('completed', donation.id);
    db.prepare('UPDATE users SET total_donated = total_donated + ? WHERE id = ?').run(donation.amount, req.user.id);

    // Get user's new rank
    const rankAfter = getUserRank(req.user.id);
    const peopleBeat = rankBefore - rankAfter;

    // Get updated user info
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    // Send notifications to users who were passed
    notifyPassedUsers(req.user.id, user.total_donated);

    res.json({
      success: true,
      peopleBeat,
      newRank: rankAfter,
      totalDonated: user.total_donated,
      badges: getAllBadges(user.total_donated),
      newBadge: getBadge(user.total_donated)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Confirmation failed' });
  }
});

// Stripe Webhook
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object;
    const userId = paymentIntent.metadata.userId;

    // Update donation
    const donation = db.prepare(
      'SELECT * FROM donations WHERE payment_id = ?'
    ).get(paymentIntent.id);

    if (donation && donation.status !== 'completed') {
      db.prepare('UPDATE donations SET status = ? WHERE id = ?').run('completed', donation.id);
      db.prepare('UPDATE users SET total_donated = total_donated + ? WHERE id = ?').run(donation.amount, userId);

      // Notify passed users
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      notifyPassedUsers(userId, user.total_donated);
    }
  }

  res.json({ received: true });
});

// PayPal payment confirmation
app.post('/api/payments/paypal-confirm', authenticateToken, async (req, res) => {
  try {
    const { orderId, amount } = req.body;

    if (!orderId || !amount) {
      return res.status(400).json({ error: 'Missing order ID or amount' });
    }

    const amountInCents = Math.round(amount * 100);

    // Get user's current rank before update
    const rankBefore = getUserRank(req.user.id);

    // Create donation record
    const donationId = uuidv4();
    db.prepare(
      'INSERT INTO donations (id, user_id, amount, payment_method, payment_id, status) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(donationId, req.user.id, amountInCents, 'paypal', orderId, 'completed');

    // Update user total
    db.prepare('UPDATE users SET total_donated = total_donated + ? WHERE id = ?').run(amountInCents, req.user.id);

    // Get user's new rank
    const rankAfter = getUserRank(req.user.id);
    const peopleBeat = rankBefore - rankAfter;

    // Get updated user info
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

    // Send notifications to users who were passed
    notifyPassedUsers(req.user.id, user.total_donated);

    res.json({
      success: true,
      peopleBeat,
      newRank: rankAfter,
      totalDonated: user.total_donated,
      badges: getAllBadges(user.total_donated),
      newBadge: getBadge(user.total_donated)
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'PayPal confirmation failed' });
  }
});

// Create crypto payment (NOWPayments integration)
app.post('/api/payments/crypto-create', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount || amount < 1) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const amountInCents = Math.round(amount * 100);

    // Create pending donation record
    const donationId = uuidv4();
    db.prepare(
      'INSERT INTO donations (id, user_id, amount, payment_method, status) VALUES (?, ?, ?, ?, ?)'
    ).run(donationId, req.user.id, amountInCents, 'crypto', 'pending');

    // In production, you would call NOWPayments API here
    // For now, return a placeholder URL
    const nowpaymentsApiKey = process.env.NOWPAYMENTS_API_KEY;

    if (nowpaymentsApiKey) {
      // Real NOWPayments integration
      const response = await fetch('https://api.nowpayments.io/v1/invoice', {
        method: 'POST',
        headers: {
          'x-api-key': nowpaymentsApiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          price_amount: amount,
          price_currency: 'eur',
          order_id: donationId,
          order_description: 'Just Because You Can - Donation',
          ipn_callback_url: `${process.env.APP_URL || 'http://localhost:3000'}/api/webhooks/nowpayments`,
          success_url: `${process.env.APP_URL || 'http://localhost:3000'}?crypto_success=true`,
          cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}?crypto_cancel=true`
        })
      });

      const data = await response.json();
      if (data.invoice_url) {
        return res.json({ paymentUrl: data.invoice_url, donationId });
      }
    }

    // Fallback: Return placeholder for testing
    res.json({
      paymentUrl: `https://nowpayments.io/payment/?amount=${amount}&currency=eur&order_id=${donationId}`,
      donationId,
      message: 'Configure NOWPAYMENTS_API_KEY in .env for live payments'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Crypto payment initialization failed' });
  }
});

// NOWPayments IPN Webhook
app.post('/api/webhooks/nowpayments', express.json(), async (req, res) => {
  try {
    const { order_id, payment_status, actually_paid } = req.body;

    if (payment_status === 'finished' || payment_status === 'confirmed') {
      const donation = db.prepare('SELECT * FROM donations WHERE id = ?').get(order_id);

      if (donation && donation.status === 'pending') {
        // Update donation status
        db.prepare('UPDATE donations SET status = ? WHERE id = ?').run('completed', donation.id);
        db.prepare('UPDATE users SET total_donated = total_donated + ? WHERE id = ?').run(donation.amount, donation.user_id);

        // Notify passed users
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(donation.user_id);
        notifyPassedUsers(donation.user_id, user.total_donated);
      }
    }

    res.json({ received: true });
  } catch (err) {
    console.error('NOWPayments webhook error:', err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// ============ LEADERBOARD ROUTES ============

function getUserRank(userId) {
  const user = db.prepare('SELECT total_donated FROM users WHERE id = ?').get(userId);
  if (!user) return null;

  const rank = db.prepare(
    'SELECT COUNT(*) + 1 as rank FROM users WHERE total_donated > ?'
  ).get(user.total_donated);

  return rank.rank;
}

// Get leaderboard
app.get('/api/leaderboard', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;

  const users = db.prepare(`
    SELECT id, display_name, country, total_donated, created_at
    FROM users
    WHERE total_donated > 0
    ORDER BY total_donated DESC, created_at ASC
    LIMIT ? OFFSET ?
  `).all(limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM users WHERE total_donated > 0').get();

  const leaderboard = users.map((user, index) => ({
    rank: offset + index + 1,
    displayName: user.display_name,
    country: user.country,
    totalDonated: user.total_donated,
    badge: getBadge(user.total_donated),
    allBadges: getAllBadges(user.total_donated)
  }));

  // Country leaderboard
  const countryStats = db.prepare(`
    SELECT country, SUM(total_donated) as total, COUNT(*) as donors
    FROM users
    WHERE total_donated > 0 AND country IS NOT NULL
    GROUP BY country
    ORDER BY total DESC
    LIMIT 10
  `).all();

  res.json({
    leaderboard,
    total: total.count,
    badges: BADGES,
    countries: countryStats
  });
});

// Get user's position
app.get('/api/leaderboard/position', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const rank = getUserRank(req.user.id);
  const total = db.prepare('SELECT COUNT(*) as count FROM users WHERE total_donated > 0').get();

  // Get users ahead
  const ahead = db.prepare(`
    SELECT display_name, total_donated
    FROM users
    WHERE total_donated > ?
    ORDER BY total_donated ASC
    LIMIT 3
  `).all(user.total_donated);

  // Get users behind
  const behind = db.prepare(`
    SELECT display_name, total_donated
    FROM users
    WHERE total_donated < ? AND total_donated > 0
    ORDER BY total_donated DESC
    LIMIT 3
  `).all(user.total_donated);

  res.json({
    rank,
    totalDonated: user.total_donated,
    totalParticipants: total.count,
    badge: getBadge(user.total_donated),
    allBadges: getAllBadges(user.total_donated),
    ahead: ahead.map(u => ({ displayName: u.display_name, totalDonated: u.total_donated })),
    behind: behind.map(u => ({ displayName: u.display_name, totalDonated: u.total_donated }))
  });
});

// ============ NOTIFICATION SYSTEM ============

async function notifyPassedUsers(donorId, newTotal) {
  // Find users who were just passed
  const passedUsers = db.prepare(`
    SELECT id, email, display_name, total_donated
    FROM users
    WHERE total_donated < ?
    AND total_donated > 0
    AND notifications_enabled = 1
    AND id != ?
  `).all(newTotal, donorId);

  const donor = db.prepare('SELECT display_name FROM users WHERE id = ?').get(donorId);

  for (const user of passedUsers) {
    // Count how many people are now ahead of this user
    const aheadCount = db.prepare(
      'SELECT COUNT(*) as count FROM users WHERE total_donated > ?'
    ).get(user.total_donated);

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_FROM || 'noreply@justbecauseyoucan.com',
        to: user.email,
        subject: 'Someone just passed you on the leaderboard! 🏆',
        html: `
          <h2>Hey ${user.display_name}!</h2>
          <p><strong>${donor.display_name}</strong> just donated and passed you on the leaderboard.</p>
          <p>You now have <strong>${aheadCount.count}</strong> people ahead of you.</p>
          <p>Your current total: <strong>€${(user.total_donated / 100).toFixed(2)}</strong></p>
          <p><a href="${process.env.APP_URL || 'http://localhost:3000'}">Reclaim your spot!</a></p>
          <p style="color: #888; font-size: 12px;">Just because you can.</p>
        `
      });
    } catch (err) {
      console.error('Failed to send notification email:', err);
    }
  }
}

// ============ STATS ============

app.get('/api/stats', (req, res) => {
  const totalDonated = db.prepare('SELECT SUM(total_donated) as total FROM users').get();
  const totalDonors = db.prepare('SELECT COUNT(*) as count FROM users WHERE total_donated > 0').get();
  const totalDonations = db.prepare('SELECT COUNT(*) as count FROM donations WHERE status = ?').get('completed');

  res.json({
    totalDonated: totalDonated.total || 0,
    totalDonors: totalDonors.count,
    totalDonations: totalDonations.count
  });
});

// ============ ADMIN ROUTES ============

// Admin auth middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    if (!verified.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.admin = verified;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    if (!admin) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: admin.id, username: admin.username, isAdmin: true }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ token, username: admin.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (admin)
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, email, display_name, total_donated, created_at, notifications_enabled
    FROM users
    ORDER BY total_donated DESC
  `).all();

  res.json(users.map(u => ({
    id: u.id,
    email: u.email,
    displayName: u.display_name,
    totalDonated: u.total_donated,
    createdAt: u.created_at,
    notificationsEnabled: u.notifications_enabled,
    badge: getBadge(u.total_donated)
  })));
});

// Get all donations (admin)
app.get('/api/admin/donations', authenticateAdmin, (req, res) => {
  const donations = db.prepare(`
    SELECT d.*, u.email, u.display_name
    FROM donations d
    LEFT JOIN users u ON d.user_id = u.id
    ORDER BY d.created_at DESC
  `).all();

  res.json(donations.map(d => ({
    id: d.id,
    userId: d.user_id,
    userEmail: d.email,
    userDisplayName: d.display_name,
    amount: d.amount,
    currency: d.currency,
    paymentMethod: d.payment_method,
    status: d.status,
    createdAt: d.created_at
  })));
});

// Update user (admin) - for editing leaderboard
app.put('/api/admin/users/:userId', authenticateAdmin, (req, res) => {
  try {
    const { userId } = req.params;
    const { displayName, totalDonated, notificationsEnabled } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update fields
    if (displayName !== undefined) {
      db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, userId);
    }
    if (totalDonated !== undefined) {
      db.prepare('UPDATE users SET total_donated = ? WHERE id = ?').run(Math.round(totalDonated), userId);
    }
    if (notificationsEnabled !== undefined) {
      db.prepare('UPDATE users SET notifications_enabled = ? WHERE id = ?').run(notificationsEnabled ? 1 : 0, userId);
    }

    const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    res.json({
      id: updatedUser.id,
      email: updatedUser.email,
      displayName: updatedUser.display_name,
      totalDonated: updatedUser.total_donated,
      notificationsEnabled: updatedUser.notifications_enabled
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user (admin)
app.delete('/api/admin/users/:userId', authenticateAdmin, (req, res) => {
  try {
    const { userId } = req.params;

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Delete user's donations first
    db.prepare('DELETE FROM donations WHERE user_id = ?').run(userId);
    // Delete user
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add manual donation (admin)
app.post('/api/admin/donations', authenticateAdmin, (req, res) => {
  try {
    const { userId, amount, note } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const amountInCents = Math.round(amount * 100);
    const donationId = uuidv4();

    db.prepare(
      'INSERT INTO donations (id, user_id, amount, payment_method, status) VALUES (?, ?, ?, ?, ?)'
    ).run(donationId, userId, amountInCents, 'admin_manual', 'completed');

    db.prepare('UPDATE users SET total_donated = total_donated + ? WHERE id = ?').run(amountInCents, userId);

    res.json({ success: true, donationId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete donation (admin)
app.delete('/api/admin/donations/:donationId', authenticateAdmin, (req, res) => {
  try {
    const { donationId } = req.params;

    const donation = db.prepare('SELECT * FROM donations WHERE id = ?').get(donationId);
    if (!donation) {
      return res.status(404).json({ error: 'Donation not found' });
    }

    // Subtract from user total if donation was completed
    if (donation.status === 'completed') {
      db.prepare('UPDATE users SET total_donated = total_donated - ? WHERE id = ?').run(donation.amount, donation.user_id);
    }

    db.prepare('DELETE FROM donations WHERE id = ?').run(donationId);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin stats
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const totalDonated = db.prepare('SELECT SUM(total_donated) as total FROM users').get();
  const totalDonations = db.prepare('SELECT COUNT(*) as count FROM donations WHERE status = ?').get('completed');
  const pendingDonations = db.prepare('SELECT COUNT(*) as count FROM donations WHERE status = ?').get('pending');

  // Recent activity
  const recentDonations = db.prepare(`
    SELECT d.*, u.display_name
    FROM donations d
    LEFT JOIN users u ON d.user_id = u.id
    WHERE d.status = 'completed'
    ORDER BY d.created_at DESC
    LIMIT 10
  `).all();

  res.json({
    totalUsers: totalUsers.count,
    totalDonated: totalDonated.total || 0,
    totalDonations: totalDonations.count,
    pendingDonations: pendingDonations.count,
    recentDonations: recentDonations.map(d => ({
      id: d.id,
      displayName: d.display_name,
      amount: d.amount,
      createdAt: d.created_at
    }))
  });
});

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
