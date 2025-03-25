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
  origin: process.env.FRONTEND_URL, // Allow your frontend URL to make requests
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
    rejectUnauthorized: false // Allow self-signed certificates for development
  }
});


pool.connect(err => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    return;
  }
  console.log('Connected to PostgreSQL Database');
});


// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // Use any email service provider
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASSWORD,  // Your email password or app-specific password
  },
});


const createTableIfNotExists = async () => {
  try {
    // Ensure the table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        idusers SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        usertype VARCHAR(50) NOT NULL,
        firstname VARCHAR(100),
        lastname VARCHAR(100),
        birthdate DATE,
        contact VARCHAR(50),
        address TEXT,
        gender VARCHAR(20),
        allergies TEXT,
        medicalhistory TEXT,
        is_verified BOOLEAN DEFAULT FALSE
      );
    `);

    // Ensure the verification_code column exists
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_code VARCHAR(10);
    `);

    console.log("Table 'users' ensured to exist.");
  } catch (err) {
    console.error("Error creating table:", err);
  }
};



// Middleware to create the table before processing each request
const checkAndCreateTable = async (req, res, next) => {
  await createTableIfNotExists();
  next(); // Proceed to the next middleware/route handler
};


app.use(checkAndCreateTable);


// Register route
app.post("/register", async (req, res) => {
  const { username, email, password, usertype } = req.body;


  if (!username || !email || !password || !usertype) {
    return res.status(400).json({ message: "All fields (email, password, usertype, username) are required" });
  }


  try {
    // Check if the email already exists
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);


    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }


    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);


    // Insert the new user into the database
    const newUser = await pool.query(
      "INSERT INTO users (username, email, password, usertype) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, email, hashedPassword, usertype]
    );


    // Generate a verification code and send it via email
    const verificationCode = crypto.randomBytes(3).toString('hex'); // Random 6-character code
    await pool.query("UPDATE users SET verification_code = $1 WHERE email = $2", [verificationCode, email]);


    // Send verification email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email Address',
      text: `Your verification code is: ${verificationCode}`
    });


    res.status(201).json({
      message: "User registered successfully. Please check your email for verification.",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Error in /register:", err.message);
    res.status(500).json({ message: "Internal server error", error: err.message });
  }
});


// Route to send verification code (in case the user needs it again)
app.post("/send-verification-code", async (req, res) => {
  const { email } = req.body;


  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }


  try {
    const verificationCode = crypto.randomBytes(3).toString('hex'); // Random 6-character code


    // Store the verification code in the database for the user
    await pool.query("UPDATE users SET verification_code = $1 WHERE email = $2", [verificationCode, email]);


    // Send the verification code email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verify Your Email Address',
      text: `Your verification code is: ${verificationCode}`,
    });


    res.status(200).json({ message: 'Verification code sent to your email.' });
  } catch (err) {
    console.error("Error sending verification code:", err.message);
    res.status(500).json({ message: "Failed to send verification email." });
  }
});


// Route to verify the code
app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;


  if (!email || !code) {
    return res.status(400).json({ message: "Email and code are required." });
  }


  try {
    // Get the stored verification code from the database
    const result = await pool.query("SELECT verification_code FROM users WHERE email = $1", [email]);


    if (result.rows.length === 0) {
      return res.status(400).json({ message: "No user found with this email." });
    }


    const storedCode = result.rows[0].verification_code;


    // Check if the code matches
    if (storedCode !== code) {
      return res.status(400).json({ message: "Invalid verification code." });
    }


    // Mark the user as verified
    await pool.query("UPDATE users SET is_verified = TRUE WHERE email = $1", [email]);


    res.status(200).json({ message: "Email successfully verified." });
  } catch (err) {
    console.error("Error verifying code:", err.message);
    res.status(500).json({ message: "Internal server error." });
  }
});


// User Login Endpoint
app.post('/api/app/login', [
  body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });


  const { username, password } = req.body;


  const query = 'SELECT * FROM users WHERE username = $1';


  pool.query(query, [username], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error querying database' });
    }


    if (result.rows.length === 0) {
      return res.status(400).json({ message: `User not found.` });
    }


    const user = result.rows[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ message: 'Error comparing passwords' });
      }


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
    });
  });
});


// Start the Server
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});





