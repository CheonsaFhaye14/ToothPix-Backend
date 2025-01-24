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
    rejectUnauthorized: false  // Allow self-signed certificates for development
  }
});

pool.connect(err => {
  if (err) {
    console.error('Error connecting to the database:', err.message);
    return;
  }
  console.log('Connected to PostgreSQL Database');
});

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access Denied. No Token Provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid Token' });
    req.user = user;
    next();
  });
};

// User Registration Endpoint
// Define saltRounds
const saltRounds = 10;


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

    // Hash the password
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

// Get All Services
app.get('/api/app/services', (req, res) => {
  const query = 'SELECT * FROM service';  // Assuming there is a service table

  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching services:', err.message);
      return res.status(500).json({ message: 'Error fetching services', error: err.message });
    }

    res.status(200).json({ message: 'Services fetched successfully', services: results.rows });
  });
});

// Add Service
app.post('/api/app/services', [
  body('name').isLength({ min: 3 }).withMessage('Service name must be at least 3 characters long'),
  body('price').isDecimal().withMessage('Price must be a valid number'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, description, price } = req.body;
  const query = 'INSERT INTO service (name, description, price) VALUES ($1, $2, $3) RETURNING idservice, name, description, price';

  pool.query(query, [name, description, price], (err, result) => {
    if (err) {
      console.error('Error adding service:', err.message);
      return res.status(500).json({ message: 'Error adding service', error: err.message });
    }

    const service = result.rows[0];
    res.status(201).json({
      message: 'Service added successfully',
      service,
    });
  });
});

// Delete Service
app.delete('/api/app/services/:id', (req, res) => {
  const serviceId = req.params.id;
  const query = 'DELETE FROM service WHERE idservice = $1';

  pool.query(query, [serviceId], (err, result) => {
    if (err) {
      console.error('Error deleting service:', err.message);
      return res.status(500).json({ message: 'Error deleting service', error: err.message });
    }

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    res.status(200).json({ message: 'Service deleted successfully' });
  });
});

//editing service
  app.put('/api/app/services/:id', [
  body('name').optional().isLength({ min: 3 }).withMessage('Service name must be at least 3 characters long'),
  body('price').optional().isDecimal().withMessage('Price must be a valid number'),
  body('description').optional().isLength({ min: 1 }).withMessage('Description must not be empty'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const serviceId = parseInt(req.params.id, 10); // Parse and validate the ID as an integer
  if (isNaN(serviceId)) {
    return res.status(400).json({ message: 'Invalid service ID' });
  }

  const { name, description, price } = req.body;

  // Dynamically build the SET clause
  const updates = [];
  const values = [];

  if (name) {
    updates.push(`name = $${updates.length + 1}`);
    values.push(name);
  }
  if (description) {
    updates.push(`description = $${updates.length + 1}`);
    values.push(description);
  }
  if (price) {
    updates.push(`price = $${updates.length + 1}`);
    values.push(price);
  }

  // Ensure at least one field is being updated
  if (updates.length === 0) {
    return res.status(400).json({ message: 'No fields provided for update' });
  }

  // Add the service ID to the values array
  values.push(serviceId);

  // Update query for PostgreSQL
  const query = `
    UPDATE service
    SET ${updates.join(', ')}
    WHERE idservice = $${values.length}
    RETURNING *`;

  try {
    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    res.status(200).json({
      message: 'Service updated successfully',
      service: result.rows[0],
    });
  } catch (err) {
    console.error('Error updating service:', err.message);
    res.status(500).json({ message: 'Error updating service', error: err.message });
  }
});


const updatePastAppointments = async () => {
  const today = new Date();
  const result = await Appointment.updateMany(
    { date: { $lt: today }, status: { $ne: 'D' } },
    { status: 'D' }
  );
  return result;
};


app.post('/api/app/profile', authenticateToken, [
  body('firstname').optional().isLength({ min: 1 }).withMessage('First name is required'),
  body('lastname').optional().isLength({ min: 1 }).withMessage('Last name is required'),
  body('birthdate').optional().isDate().withMessage('Invalid date format'),
  body('contact').optional().isLength({ min: 1 }).withMessage('Contact is required'),
  body('address').optional().isLength({ min: 1 }).withMessage('Address is required'),
  body('gender').optional().isLength({ min: 1 }).withMessage('Gender is required'),
  body('allergies').optional().isLength({ min: 1 }).withMessage('Allergies are required'),
  body('medicalhistory').optional().isLength({ min: 1 }).withMessage('Medical history is required'),
  body('email').optional().isEmail().withMessage('Invalid email format'),
  body('username').optional().isLength({ min: 1 }).withMessage('Username is required'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const userId = req.user.userId; // Get user ID from the authenticated token
  const { firstname, lastname, birthdate, contact, address, gender, username, email, allergies, medicalhistory } = req.body;

  const updates = [];
  const values = [];

  // Dynamically construct the SET clause and values
  if (firstname) {
    updates.push(`firstname = $${updates.length + 1}`);
    values.push(firstname);
  }
  if (lastname) {
    updates.push(`lastname = $${updates.length + 1}`);
    values.push(lastname);
  }
  if (birthdate) {
    updates.push(`birthdate = $${updates.length + 1}`);
    values.push(birthdate);
  }
  if (contact) {
    updates.push(`contact = $${updates.length + 1}`);
    values.push(contact);
  }
  if (address) {
    updates.push(`address = $${updates.length + 1}`);
    values.push(address);
  }
  if (gender) {
    updates.push(`gender = $${updates.length + 1}`);
    values.push(gender);
  }
  if (username) {
    updates.push(`username = $${updates.length + 1}`);
    values.push(username);
  }
  if (email) {
    updates.push(`email = $${updates.length + 1}`);
    values.push(email);
  }
  if (allergies) {
    updates.push(`allergies = $${updates.length + 1}`);
    values.push(allergies);
  }
  if (medicalhistory) {
    updates.push(`medicalhistory = $${updates.length + 1}`);
    values.push(medicalhistory);
  }

  if (updates.length === 0) {
    return res.status(400).json({ message: 'No fields provided for update' });
  }

  // Add the userId as the last parameter for the WHERE clause
  values.push(userId);

  // Construct the query
  const query = `UPDATE users SET ${updates.join(', ')} WHERE idusers = $${values.length} RETURNING *`;

  // Execute the query
  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating profile:', err.message);
      return res.status(500).json({ message: 'Error updating profile', error: err.message });
    }

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Profile updated successfully', user: result.rows[0] });
  });
});


app.get('/api/app/profile/:idusers', authenticateToken, (req, res) => {
  const userId = req.params.idusers; // Extract user ID from the request parameters
  const query = 'SELECT * FROM users WHERE idusers = $1'; // Use $1 for parameterized queries

  pool.query(query, [userId], (err, result) => {
    if (err) {
      console.error('Error fetching profile:', err.message);
      return res.status(500).json({ message: 'Error fetching profile', error: err.message });
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ profile: result.rows[0] }); // Send all fields in the response
  });
});


app.post('/api/app/appointments', (req, res) => {
  console.log("Received Appointment Data:", req.body); // Log received data

  const { idpatient, iddentist, idservice, date, status, notes } = req.body;

  // Validate required fields
  if (!idpatient || !iddentist || !idservice || !date || !status) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const query = `
    INSERT INTO appointment (idpatient, iddentist, idservice, date, status, notes) 
    VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING idappointment, idpatient, iddentist, idservice, date, status, notes
  `;

  pool.query(
    query,
    [idpatient, iddentist, idservice, date, status, notes || null], // Provide values for placeholders
    (err, result) => {
      if (err) {
        console.error('Error creating appointment:', err.message); // Log the error
        return res.status(500).json({
          message: 'Error creating appointment',
          error: err.message,
        });
      }

      res.status(201).json({
        message: 'Appointment created successfully',
        appointment: result.rows[0], // Return the created appointment details
      });
    }
  );
});


app.delete('/api/app/appointments/:id', (req, res) => { 
  const idappointment = req.params.id;

  if (!idappointment) {
    return res.status(400).json({ message: 'Appointment ID is required' });
  }

  const query = 'DELETE FROM appointment WHERE idappointment = $1';

  pool.query(query, [idappointment], (err, result) => {
    if (err) {
      console.error('Error deleting appointment:', err.message); // Log the error for debugging
      return res.status(500).json({
        message: 'Error deleting appointment',
        error: err.message,
      });
    }

    if (result.rowCount === 0) { // PostgreSQL uses `rowCount` instead of `affectedRows`
      return res.status(404).json({ message: 'Appointment not found' });
    }

    res.status(200).json({ message: 'Appointment deleted successfully' });
  });
});

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

app.get('/api/app/appointmentsrecord/:idpatient', (req, res) => {
  const idpatient = parseInt(req.params.idpatient, 10); // Parse as an integer
  
  if (isNaN(idpatient)) {
    return res.status(400).json({ message: 'Invalid idpatient: Must be an integer' });
  }

  const query = `
    SELECT 
      a.idappointment, 
      a.notes, 
      s.price AS service_price
    FROM appointment a
    JOIN service s ON a.idservice = s.idservice
    WHERE a.idpatient = $1 AND a.status = 'D'
  `;

  pool.query(query, [idpatient], (err, result) => {
    if (err) {
      console.error('Error fetching appointments:', err.message); // Log error for debugging
      return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No completed appointments found' });
    }

    // Format the response to match the frontend's expected structure
    res.status(200).json({
      appointments: result.rows.map((appointment) => ({
        idappointment: appointment.idappointment,
        notes: appointment.notes,
        service_price: appointment.service_price, // Ensure service_price is included
      })),
    });
  });
});


app.get('/api/app/summary', (req, res) => {
  const idusers = req.query.idusers; // Extract idusers from the request query parameters
  
  if (!idusers) {
    return res.status(400).json({ message: 'Missing idusers parameter' });
  }

  const query = `
    SELECT 
      COALESCE(COUNT(CASE WHEN status = 'N' THEN 1 END), 0) AS total_appointments,
      COALESCE(COUNT(CASE WHEN status = 'D' THEN 1 END), 0) AS total_clinic_visits
    FROM appointment
    WHERE idpatient = $1
  `;

  pool.query(query, [idusers], (err, result) => {
    if (err) {
      console.error('Error fetching summary:', err.message); // Log error for debugging
      return res.status(500).json({ message: 'Error fetching summary', error: err.message });
    }

    const summary = result.rows[0] || { total_appointments: 0, total_clinic_visits: 0 }; // Handle empty results
    res.status(200).json({
      total_appointments: summary.total_appointments,
      total_clinic_visits: summary.total_clinic_visits,
    });
  });
});


app.get('/api/app/dentists', (req, res) => {
  const query = `
    SELECT idusers, firstname, lastname 
    FROM users 
    WHERE usertype = 'dentist'
  `;

  pool.query(query, (err, result) => {
    if (err) {
      console.error('Error fetching dentists:', err.message); // Log error for debugging
      return res.status(500).json({ message: 'Error fetching dentists', error: err.message });
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No dentists found' });
    }

    // Add a 'name' property to each dentist by combining firstname and lastname
    const dentistsWithNames = result.rows.map(dentist => ({
      ...dentist,
      name: `${dentist.firstname} ${dentist.lastname}`, // Combine firstname and lastname
    }));

    res.status(200).json({ dentists: dentistsWithNames });
  });
});


app.get('/api/app/patients', (req, res) => {
  const query = `
    SELECT idusers, firstname, lastname 
    FROM users 
    WHERE usertype = 'patient'
  `;

  pool.query(query, (err, result) => {
    if (err) {
      console.error('Error fetching patients:', err.message); // Log error for debugging
      return res.status(500).json({ message: 'Error fetching patients', error: err.message });
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No patients found' });
    }

    // Add a 'name' property to each patient by combining firstname and lastname
    const patientsWithNames = result.rows.map(patient => ({
      ...patient,
      name: `${patient.firstname} ${patient.lastname}`, // Combine firstname and lastname
    }));

    res.status(200).json({ patients: patientsWithNames });
  });
});



// Get All Appointments Data
app.get('/api/app/appointments', (req, res) => {
  const query = 'SELECT * FROM appointment';

  pool.query(query, (err, result) => {
    if (err) {
      console.error('Error fetching appointments:', err.message); // Log error for debugging
      return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    // Return all appointment data
    res.status(200).json({ appointments: result.rows });
  });
});







// Start the Server
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});
