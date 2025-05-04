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
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
};
app.use(cors(corsOptions));
app.use(bodyParser.json());

// PostgreSQL connection setup
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

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const { authorization } = req.headers;
  if (!authorization) return res.status(401).json({ message: "No token provided" });

  const token = authorization.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Store userId in request object for next routes
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Token invalid or expired' });
  }
};
// ✅ Get all dentists (users with usertype = 'dentist')
app.get('/api/app/dentists', async (req, res) => {
  const query = "SELECT idUsers, firstname, lastname FROM users WHERE usertype = 'dentist'";

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No dentists found' });
    }

    res.status(200).json({
      dentists: result.rows
    });
  } catch (err) {
    console.error('Error fetching dentists:', err.message);
    res.status(500).json({ message: 'Error fetching dentists', error: err.message });
  }
});

// ✅ Update appointment status, note, and date via /appointments/:id
app.put('/api/app/appointments/:id', async (req, res) => {
  const id = req.params.id;
  const { status, note, date } = req.body; // Receive status, note, and date from the request body

  // Initialize an array for the set values (dynamically)
  const setValues = [];
  const queryParams = [];

  let query = 'UPDATE appointment SET ';

  // Check if status is provided and valid
  if (status && ['approved', 'cancelled', 'rescheduled'].includes(status)) {
    setValues.push('status = $' + (setValues.length + 1)); // Add status to setValues
    queryParams.push(status);
  }

  // Check if note is provided
  if (note !== undefined) {
    setValues.push('note = $' + (setValues.length + 1)); // Add note to setValues
    queryParams.push(note);
  }

  // Check if date is provided and valid
  if (date && !isNaN(Date.parse(date))) {
    setValues.push('date = $' + (setValues.length + 1)); // Add date to setValues
    queryParams.push(date);
  }

  // If no fields were provided to update, return an error
  if (setValues.length === 0) {
    return res.status(400).json({ message: 'No valid fields to update' });
  }

  // Build the final query with placeholders for the values
  query += setValues.join(', ') + ' WHERE idappointment = $' + (setValues.length + 1);
  queryParams.push(id);

  try {
    const result = await pool.query(query, queryParams);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found.' });
    }

    res.json({
      message: `Appointment updated successfully`,
      appointment: result.rows[0],
    });
  } catch (err) {
    console.error('Error updating appointment:', err.message);
    res.status(500).json({
      message: 'Error updating appointment',
      error: err.message,
    });
  }
});



// Register route
app.post("/register", async (req, res) => {
  const { username, email, password, usertype } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!username || !email || !password || !usertype) {
    return res.status(400).json({ message: "All fields are required" });
  }

  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  try {
    const existingEmail = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingEmail.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const existingUsername = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (existingUsername.rows.length > 0) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const similarUsernameCheck = await pool.query("SELECT * FROM users WHERE username ILIKE $1", [username]);
    if (similarUsernameCheck.rows.length > 0) {
      return res.status(400).json({ message: "Username is too similar to an existing username" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
      "INSERT INTO users (username, email, password, usertype) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, email, hashedPassword, usertype]
    );

    res.status(201).json({
      message: "User registered successfully.",
      user: newUser.rows[0],
    });
  } catch (err) {
    console.error("Error in /register:", err.message);
    res.status(500).json({ message: "Internal server error", error: err.message });
  }
});
// ✅ Create a new appointment
app.post('/api/app/appointments', async (req, res) => {
  const { idpatient, iddentist, date, status, notes, idservice } = req.body;

  // Validate required fields
  if (!idpatient || !iddentist || !date || !idservice) {
    return res.status(400).json({ message: 'idpatient, iddentist, date, and idservice are required.' });
  }

  const query = `
    INSERT INTO appointment (idpatient, iddentist, date, status, notes, idservice)
    VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING idappointment, idpatient, iddentist, date, status, notes, idservice
  `;

  try {
    const result = await pool.query(query, [idpatient, iddentist, date, status || 'pending', notes || '', idservice]);
    const appointment = result.rows[0];

    res.status(201).json({
      message: 'Appointment created successfully',
      appointment,
    });
  } catch (err) {
    console.error('Error creating appointment:', err.message);
    res.status(500).json({ message: 'Error creating appointment', error: err.message });
  }
});

// Get all appointments route
app.get('/api/app/appointments', async (req, res) => {
  const query = 'SELECT * FROM appointment';

  try {
    const result = await pool.query(query);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    res.status(200).json({
      appointments: result.rows
    });
  } catch (err) {
    console.error('Error fetching appointments:', err.message);
    res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});


// Login route
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
      return res.status(400).json({ message: 'User not found.' });
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
      user: {
        id: user.idusers,
        username: user.username,
        email: user.email,
        usertype: user.usertype,
      },
    });
  } catch (err) {
    res.status(500).json({ message: 'Error querying database' });
  }
});

// Get profile route
app.get('/api/app/profile', authenticateToken, async (req, res) => {
  try {
    const getQuery = 'SELECT * FROM users WHERE idusers = $1';
    const result = await pool.query(getQuery, [req.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      profile: result.rows[0]
    });
  } catch (err) {
    console.error("Error retrieving profile:", err.message);
    res.status(500).json({ message: 'Error retrieving profile' });
  }
});

// Update profile route
app.post('/api/app/profile', authenticateToken, async (req, res) => {
  const { firstname, lastname, birthdate, contact, address, gender, allergies, medicalhistory, email, username } = req.body;

  try {
    const updateQuery = `UPDATE users 
                         SET firstname = $1, lastname = $2, birthdate = $3, contact = $4, address = $5, gender = $6, allergies = $7, medicalhistory = $8, email = $9, username = $10
                         WHERE idusers = $11
                         RETURNING *`;

    const updatedUser = await pool.query(updateQuery, [firstname, lastname, birthdate, contact, address, gender, allergies, medicalhistory, email, username, req.userId]);

    res.status(200).json({
      message: 'Profile updated successfully',
      profile: updatedUser.rows[0]
    });
  } catch (err) {
    console.error("Error updating profile:", err.message);
    res.status(500).json({ message: 'Error updating profile' });
  }
});


// ✅ ADD SERVICE ROUTES HERE

app.post('/api/app/services', async (req, res) => {
  const { name, description, price } = req.body;

  // Basic manual checking
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }
  
  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }

  // Log input values for debugging
  console.log('Received data:', { name, description, price });

  const query = 'INSERT INTO service (name, description, price) VALUES ($1, $2, $3) RETURNING idservice, name, description, price';

  try {
    const result = await pool.query(query, [name.trim(), description, parseFloat(price)]);
    const service = result.rows[0];

    // Log successful insertion
    console.log('Service added:', service);

    res.status(201).json({
      message: 'Service added successfully',
      service,
    });
  } catch (err) {
    // Log error details for debugging
    console.error('Error adding service:', err.message);

    res.status(500).json({ 
      message: 'Error adding service', 
      error: err.message 
    });
  }
});
// Get all services route
app.get('/api/app/services', async (req, res) => {
  const query = 'SELECT * FROM service';

  try {
    const result = await pool.query(query);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No services found' });
    }

    res.status(200).json({
      services: result.rows
    });
  } catch (err) {
    console.error('Error fetching services:', err.message);
    res.status(500).json({ message: 'Error fetching services', error: err.message });
  }
});

// Update service route
app.put('/api/app/services/:id', async (req, res) => {
  const { id } = req.params;  // Service ID from URL parameter
  const { name, description, price } = req.body;  // Data from the request body

  // Validate input
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }

  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }

  // Query to update the service in the database
  const query = `
    UPDATE service 
    SET name = $1, description = $2, price = $3
    WHERE idservice = $4
    RETURNING idservice, name, description, price
  `;

  try {
    const result = await pool.query(query, [name.trim(), description, parseFloat(price), id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    const updatedService = result.rows[0];

    // Respond with the updated service data
    res.status(200).json({
      message: 'Service updated successfully',
      service: updatedService,
    });
  } catch (err) {
    console.error('Error updating service:', err.message);
    res.status(500).json({ message: 'Error updating service', error: err.message });
  }
});

// Delete Service
app.delete('/api/app/services/:id', async (req, res) => {
  const serviceId = req.params.id;
  const query = 'DELETE FROM service WHERE idservice = $1';

  try {
    const result = await pool.query(query, [serviceId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    res.status(200).json({ message: 'Service deleted successfully' });
  } catch (err) {
    console.error('Error deleting service:', err.message);
    res.status(500).json({ message: 'Error deleting service', error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});
