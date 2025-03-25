require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const { body, validationResult } = require('express-validator');


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


// Middleware to authenticate the token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied. No Token Provided.' });


  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid Token' });
    req.user = user;
    next();
  });
};


// Define saltRounds for bcrypt
const saltRounds = 10;


// User Registration Endpoint
app.post("/register", async (req, res) => {
  const { username, email, password, usertype } = req.body; // Extract username from request body


  // Ensure all required fields are provided
  if (!username || !email || !password || !usertype) {
    return res.status(400).json({ message: "All fields (email, password, usertype, username) are required" });
  }


  try {
    // Check if the email already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",  // Use $1 instead of $2
      [email]
    );


    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }


    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, saltRounds);


    // Insert the new user into the database (username is now included)
    const newUser = await pool.query(
      "INSERT INTO users (username, email, password, usertype) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, email, hashedPassword, usertype]
    );


    res.status(201).json({
      message: "User registered successfully",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Error in /register:", err.message);
    res.status(500).json({ message: "Internal server error", error: err.message });
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


  console.log("Received username:", username); // Debugging line
  const query = 'SELECT * FROM users WHERE username = $1'; // Ensure column name is correct


  pool.query(query, [username], (err, result) => {
    if (err) {
      console.error("Error querying database:", err.message); // Debugging line
      return res.status(500).json({ message: 'Error querying database' });
    }


    if (result.rows.length === 0) {
      console.log("No user found with username:", username); // Debugging line
      return res.status(400).json({ message: `User not found. Please check the username: "${username}"` });
    }


    const user = result.rows[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err.message); // Debugging line
        return res.status(500).json({ message: 'Error comparing passwords' });
      }


      if (!isMatch) {
        console.log("Invalid password for user:", username); // Debugging line
        return res.status(400).json({ message: `Incorrect password for user: "${username}"` });
      }


      const token = jwt.sign(
        { userId: user.idusers, username: user.username, usertype: user.usertype },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );


      res.status(200).json({
        message: 'Login successful',
        token: token,
        idusers: user.idusers,
        usertype: user.usertype,
        user: { id: user.idusers, username: user.username, email: user.email },
      });
    });
  });
});


// Example of another endpoint with dynamic data handling
app.put('/api/app/appointments/update-status', async (req, res) => {
  try {
    const { currentDate } = req.body; // Assume currentDate is passed in YYYY-MM-DD format


    // Validate currentDate
    if (!currentDate) {
      return res.status(400).json({ message: 'Current date is required' });
    }


    // SQL query to update appointments with past dates and status != 'D'
    const query = `
      UPDATE appointment
      SET status = 'D'
      WHERE date < $1 AND status != 'D'
      RETURNING *
    `;


    // Execute the query
    const result = await pool.query(query, [currentDate]);


    // Check if any rows were updated
    if (result.rowCount === 0) {
      return res.status(200).json({ message: 'No appointments required updating.' });
    }


    // Respond with updated rows
    res.status(200).json({
      message: 'Appointments updated successfully',
      updatedAppointments: result.rows,
    });
  } catch (error) {
    console.error('Error updating appointment status:', error.message);
    res.status(500).json({
      message: 'Error updating appointment status',
      error: error.message,
    });
  }
});


// Example of GET endpoint for fetching patients
app.get('/api/app/patients', (req, res) => {
  const query = 'SELECT * FROM users WHERE usertype = $1';


  pool.query(query, ['patient'], (err, result) => {
    if (err) {
      console.error('Error fetching patients:', err.message); // Log the error for debugging
      return res.status(500).json({ message: 'Error fetching patients', error: err.message });
    }


    if (result.rows.length === 0) { // PostgreSQL uses `rows` for results
      return res.status(404).json({ message: 'No patients found' });
    }


    res.status(200).json({ patients: result.rows }); // Use `rows` to access the query results
  });
});


// Start the Server
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});





