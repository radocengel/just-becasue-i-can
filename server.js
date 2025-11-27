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
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    display_name TEXT,
    total_donated INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    notifications_enabled INTEGER DEFAULT 1
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

  CREATE INDEX IF NOT EXISTS idx_users_total ON users(total_donated DESC);
  CREATE INDEX IF NOT EXISTS idx_donations_user ON donations(user_id);
`);

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
  { threshold: 1, name: 'Starter', emoji: '🌱', color: '#78909c' },
  { threshold: 10, name: 'Supporter', emoji: '⭐', color: '#4caf50' },
  { threshold: 100, name: 'Champion', emoji: '🏆', color: '#2196f3' },
  { threshold: 1000, name: 'Hero', emoji: '💎', color: '#9c27b0' },
  { threshold: 10000, name: 'Legend', emoji: '👑', color: '#ff9800' },
  { threshold: 100000, name: 'Titan', emoji: '🔥', color: '#f44336' },
  { threshold: 1000000, name: 'Immortal', emoji: '🌟', color: '#ffd700' }
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

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, displayName, agreeToTerms } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    if (!agreeToTerms) {
      return res.status(400).json({ error: 'You must agree to the terms' });
    }

    // Check if user exists
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const userId = uuidv4();
    db.prepare(
      'INSERT INTO users (id, email, password, display_name) VALUES (?, ?, ?, ?)'
    ).run(userId, email, hashedPassword, displayName || email.split('@')[0]);

    // Generate token
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: userId,
        email,
        displayName: displayName || email.split('@')[0],
        totalDonated: 0
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        totalDonated: user.total_donated,
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
  const user = db.prepare('SELECT id, email, display_name, total_donated FROM users WHERE id = ?').get(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    totalDonated: user.total_donated,
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
    SELECT id, display_name, total_donated, created_at
    FROM users
    WHERE total_donated > 0
    ORDER BY total_donated DESC, created_at ASC
    LIMIT ? OFFSET ?
  `).all(limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM users WHERE total_donated > 0').get();

  const leaderboard = users.map((user, index) => ({
    rank: offset + index + 1,
    displayName: user.display_name,
    totalDonated: user.total_donated,
    badge: getBadge(user.total_donated),
    allBadges: getAllBadges(user.total_donated)
  }));

  res.json({
    leaderboard,
    total: total.count,
    badges: BADGES
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

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
