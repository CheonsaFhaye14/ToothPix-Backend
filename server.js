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

app.get('/api/app/appointments/search', async (req, res) => { 
  const { dentist, patient, startDate, endDate } = req.query;

  let conditions = [];
  let values = [];

  if (dentist) {
    conditions.push(`iddentist = $${values.length + 1}`);
    values.push(dentist);
  }

  if (patient) {
    conditions.push(`idpatient = $${values.length + 1}`);
    values.push(patient);
  }

  if (startDate && endDate) {
    conditions.push(`DATE(date) BETWEEN $${values.length + 1} AND $${values.length + 2}`);
    values.push(startDate, endDate);
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const query = `SELECT * FROM appointment ${whereClause} ORDER BY date ASC`;

  try {
    const result = await pool.query(query, values);
    res.status(200).json({ appointments: result.rows });
  } catch (err) {
    res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});


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


const crypto = require('crypto');
const nodemailer = require('nodemailer');

// API to request password reset (Generate token and send email)
app.post('/api/app/admin/request-reset-password', async (req, res) => {
  const { email } = req.body;
  const token = crypto.randomBytes(20).toString('hex');
  const expiration = Date.now() + 3600000; // Token expires in 1 hour
  
  // Store the token and expiration time in the database
  const query = 'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3';
  const values = [token, expiration, email];

  try {
    const result = await pool.query(query, values);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Admin email not found' });
    }

    // Step 3: Send the reset link email
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
     auth: {
  user: process.env.EMAIL_USER,
  pass: process.env.EMAIL_PASS,
},

      },
    });

 const resetLink = `https://www.toothpix.com/reset-password?token=${token}`;
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset Request',
      text: `Click the following link to reset your password: ${resetLink}`,
    });

    res.status(200).json({ message: 'Password reset link sent.' });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Error sending reset link', error: err.message });
  }
});



app.get('/api/app/admin', async (req, res) => {
  const query = "SELECT idUsers, email, usertype, username FROM users WHERE usertype = 'admin'";

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No admin found' });
    }

    res.status(200).json({
      admin: result.rows
    });
  } catch (err) {
    console.error('Error fetching dentists:', err.message);
    res.status(500).json({ message: 'Error fetching admin', error: err.message });
  }
});

app.post('/api/app/admin', [
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
    if (user.usertype !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    const token = jwt.sign(
      { username: user.username, usertype: user.usertype },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Admin login successful',
      token: token,
      user: {
        username: user.username,
        usertype: user.usertype,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error querying database' });
  }
});

// Create a new record
app.post('/api/app/records', async (req, res) => {
  const { idpatient, iddentist, idappointment, treatment_notes, paymentstatus } = req.body;

  // Validate required fields
  if (!idpatient || !iddentist || !idappointment) {
    return res.status(400).json({ message: 'idpatient, iddentist, and idappointment are required.' });
  }

  const query = `
    INSERT INTO records (idpatient, iddentist, idappointment, treatment_notes, paymentstatus)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING idrecord, idpatient, iddentist, idappointment, treatment_notes, paymentstatus
  `;

  try {
    const result = await pool.query(query, [idpatient, iddentist, idappointment, treatment_notes, paymentstatus]);
    const record = result.rows[0];

    res.status(201).json({
      message: 'Record created successfully',
      record,
    });
  } catch (err) {
    console.error('Error creating record:', err.message);
    res.status(500).json({ message: 'Error creating record', error: err.message });
  }
});

// Get all records
app.get('/api/app/records', async (req, res) => {
  const query = 'SELECT * FROM records';

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

    res.status(200).json({
      records: result.rows
    });
  } catch (err) {
    console.error('Error fetching records:', err.message);
    res.status(500).json({ message: 'Error fetching records', error: err.message });
  }
});

// Update a record
app.put('/api/app/records/:id', async (req, res) => {
  const id = req.params.id;
  const { treatment_notes, paymentstatus } = req.body;

  // Validate input
  const allowedStatuses = ['paid', 'unpaid', 'partial'];
  if (paymentstatus && !allowedStatuses.includes(paymentstatus)) {
    return res.status(400).json({ message: 'Invalid payment status' });
  }

  const query = `
    UPDATE records 
    SET treatment_notes = $1, paymentstatus = $2
    WHERE idrecord = $3
    RETURNING idrecord, idpatient, iddentist, idappointment, treatment_notes, paymentstatus
  `;

  try {
    const result = await pool.query(query, [treatment_notes, paymentstatus, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Record not found' });
    }

    const updatedRecord = result.rows[0];

    res.status(200).json({
      message: 'Record updated successfully',
      record: updatedRecord,
    });
  } catch (err) {
    console.error('Error updating record:', err.message);
    res.status(500).json({ message: 'Error updating record', error: err.message });
  }
});

// Delete a record
app.delete('/api/app/records/:id', async (req, res) => {
  const recordId = req.params.id;
  const query = 'DELETE FROM records WHERE idrecord = $1';

  try {
    const result = await pool.query(query, [recordId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Record not found' });
    }

    res.status(200).json({ message: 'Record deleted successfully' });
  } catch (err) {
    console.error('Error deleting record:', err.message);
    res.status(500).json({ message: 'Error deleting record', error: err.message });
  }
});

app.put('/api/app/appointments/:id', async (req, res) => {
  const id = req.params.id;
  const { status, notes, date } = req.body;

  // Supported statuses
  const allowedStatuses = ['approved', 'cancelled', 'rescheduled', 'declined'];

  // Validate status
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid or missing status' });
  }

  // Auto-generate notes if not provided
  const now = new Date();
  
  // Format the date as "YYYY-MM-DD HH:mm"
  const formattedDate = now.toISOString().slice(0, 16).replace("T", " "); // e.g., "2025-05-04 21:42"

  let finalNotes = notes;

  if (!notes) {
    if (status === 'approved') {
      finalNotes = `Approved by dentist on ${formattedDate}`;
    } else if (status === 'declined' || status === 'cancelled') {
      finalNotes = `Cancelled by dentist on ${formattedDate}. Please reschedule.`;
    } else if (status === 'rescheduled' && date) {
      finalNotes = `Rescheduled to ${date}`;
    }
  }

  // Initialize query components
  const setValues = [];
  const queryParams = [];
  let query = 'UPDATE appointment SET ';

  // Set fields to update
  if (status) {
    setValues.push(`status = $${setValues.length + 1}`);
    queryParams.push(status);
  }

  if (finalNotes !== undefined) {
    setValues.push(`notes = $${setValues.length + 1}`);
    queryParams.push(finalNotes);
  }

  if (date && !isNaN(Date.parse(date))) {
    setValues.push(`date = $${setValues.length + 1}`);
    queryParams.push(date);
  }

  if (setValues.length === 0) {
    return res.status(400).json({ message: 'No valid fields to update' });
  }

  // Build final SQL query
  query += setValues.join(', ');
  query += ` WHERE idappointment = $${setValues.length + 1} RETURNING *`;
  queryParams.push(id);

  try {
    const result = await pool.query(query, queryParams);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found.' });
    }

    res.json({
      message: 'Appointment updated successfully',
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
// ✅ Get all patients (users with usertype = 'patient')
app.get('/api/app/patients', async (req, res) => {
  const query = "SELECT idUsers, firstname, lastname FROM users WHERE usertype = 'patient'";

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No patients found' });
    }

    res.status(200).json({
      patients: result.rows
    });
  } catch (err) {
    console.error('Error fetching patients:', err.message);
    res.status(500).json({ message: 'Error fetching patients', error: err.message });
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
