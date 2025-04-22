require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.APP_API_PORT || 3000;

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
};
app.use(cors(corsOptions));
app.use(bodyParser.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.connect(err => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    return;
  }
  console.log('Connected to PostgreSQL Database');
});


// Register route
app.post("/register", async (req, res) => {
  const { username, email, password, usertype } = req.body;
  if (!username || !email || !password || !usertype) {
    return res.status(400).json({ message: "All fields are required" });
  }
  try {
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = crypto.randomBytes(3).toString('hex');
    const newUser = await pool.query(
      "INSERT INTO users (username, email, password, usertype, verification_code) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [username, email, hashedPassword, usertype, verificationCode]
    );
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email Address',
      text: `Your verification code is: ${verificationCode}`
    });
    res.status(201).json({
      message: "User registered successfully. Check email for verification.",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Error in /register:", err.message);
    res.status(500).json({ message: "Internal server error", error: err.message });
  }
});

// Verify Code
app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ message: "Email and code are required." });
  }
  try {
    const result = await pool.query("SELECT verification_code FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "No user found with this email." });
    }
    if (result.rows[0].verification_code !== code) {
      return res.status(400).json({ message: "Invalid verification code." });
    }
    await pool.query("UPDATE users SET is_verified = TRUE WHERE email = $1", [email]);
    res.status(200).json({ message: "Email successfully verified." });
  } catch (err) {
    console.error("Error verifying code:", err.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

// Login
app.post('/api/app/login', [
  body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: `User not found.` });
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }
    const token = jwt.sign(
      { userId: user.idusers, username: user.username, usertype: user.usertype },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.status(200).json({
      message: 'Login successful',
      token: token,
      user: { id: user.idusers, username: user.username, email: user.email, usertype: user.usertype },
    });
  } catch (err) {
    res.status(500).json({ message: 'Error querying database' });
  }
});

app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});
