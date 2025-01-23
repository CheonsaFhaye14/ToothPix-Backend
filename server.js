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
        idUsers: user.idusers,
        usertype: user.usertype,
        user: { id: user.idusers, username: user.username, email: user.email },
      });
    });
  });
});

// Get All Services
app.get('/api/app/services', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM service';  // Assuming there is a service table

  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching services:', err.message);
      return res.status(500).json({ message: 'Error fetching services', error: err.message });
    }

    res.status(200).json({ message: 'Services fetched successfully', services: results.rows });
  });
});




app.put('/api/app/appointments/update-past', (req, res) => {
  const query = `
    UPDATE appointment
    SET status = 'D'
    WHERE date < CURDATE() AND status != 'D'
  `;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({
        message: 'Error updating past appointments',
        error: err.message,
      });
    }

    res.status(200).json({
      message: 'Past appointments updated successfully',
      affectedRows: results.affectedRows,
    });
  });
});


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

  const userId = req.user.userId;
  const { firstname, lastname, birthdate, contact, address, gender, username, email, allergies, medicalhistory } = req.body;

  // Prepare the update object, excluding password
  const updates = {};

  if (firstname) updates.firstname = firstname;
  if (lastname) updates.lastname = lastname;
  if (birthdate) updates.birthdate = birthdate;
  if (contact) updates.contact = contact;
  if (address) updates.address = address;
  if (gender) updates.gender = gender;
  if (username) updates.username = username;
  if (email) updates.email = email;
  if (allergies) updates.allergies = allergies;
  if (medicalhistory) updates.medicalhistory = medicalhistory;

  // Update the user profile without modifying the password
  const query = 'UPDATE users SET ? WHERE idUsers = ?';
  db.query(query, [updates, userId], (err) => {
    if (err) return res.status(500).json({ message: 'Error updating profile', error: err.message });
    res.status(200).json({ message: 'Profile updated successfully' });
  });
});


app.get('/api/app/profile/:idUsers', authenticateToken, (req, res) => {
  const userId = req.params.idUsers;
  const query = 'SELECT * FROM users WHERE idUsers = ?'; // Query all fields for the user

  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Error fetching profile', error: err.message });
    if (results.length === 0) return res.status(404).json({ message: 'User not found' });

    res.status(200).json({ profile: results[0] }); // Send all fields
  });
});

app.put('/api/app/services/:id', [
  body('name').optional().isLength({ min: 3 }).withMessage('Service name must be at least 3 characters long'),
  body('price').optional().isDecimal().withMessage('Price must be a valid number'),
  body('description').optional().isLength({ min: 1 }).withMessage('Description must not be empty'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const serviceId = req.params.id;  // This is where the service ID comes in
  const { name, description, price } = req.body;

  const updates = {};
  if (name) updates.name = name;
  if (description) updates.description = description;
  if (price) updates.price = price;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ message: 'No fields provided for update' });
  }

  const query = 'UPDATE service SET ? WHERE idservice = ?';
  db.query(query, [updates, serviceId], (err, result) => {
    if (err) return res.status(500).json({ message: 'Error updating service', error: err.message });
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }
    res.status(200).json({ message: 'Service updated successfully' });
  });
});



// CRUD Operations for Services

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
  const query = 'INSERT INTO service (name, description, price) VALUES (?, ?, ?)';

  db.query(query, [name, description, price], (err, result) => {
    if (err) return res.status(500).json({ message: 'Error adding service', error: err.message });

    res.status(201).json({
      message: 'Service added successfully',
      service: { idservice: result.insertId, name, description, price },
    });
  });
});


app.post('/api/app/appointments', (req, res) => {
  console.log("Received Appointment Data:", req.body);  // Log received data

  const { idpatient, iddentist, idservice, date, status, notes } = req.body;

  if (!idpatient || !iddentist || !idservice || !date || !status) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const query = `
    INSERT INTO appointment (idpatient, iddentist, idservice, date, status, notes) 
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [idpatient, iddentist, idservice, date, status, notes || null],
    (err, result) => {
      if (err) {
        return res.status(500).json({
          message: 'Error creating appointment',
          error: err.message,
        });
      }

      res.status(201).json({
        message: 'Appointment created successfully',
        appointment: {
          idappointment: result.insertId,
          idpatient,
          iddentist,
          idservice,
          date,
          status,
          notes,
        },
      });
    }
  );
});



// Delete Service
app.delete('/api/app/services/:id', (req, res) => {
  const serviceId = req.params.id;
  const query = 'DELETE FROM service WHERE idservice = ?';

  db.query(query, [serviceId], (err) => {
    if (err) return res.status(500).json({ message: 'Error deleting service', error: err.message });

    res.status(200).json({ message: 'Service deleted successfully' });
  });
});

app.post('/api/app/appointments', authenticateToken, (req, res) => {
  const { idpatient, iddentist, idservice, date, status, notes } = req.body;

  if (!idpatient || !iddentist || !idservice || !date || !status) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  const query = `
    INSERT INTO appointment (idpatient, iddentist, idservice, date, status, notes) 
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  
  db.query(
    query,
    [idpatient, iddentist, idservice, date, status, notes || null],
    (err, result) => {
      if (err) {
        return res.status(500).json({
          message: 'Error creating appointment',
          error: err.message,
        });
      }

      res.status(201).json({
        message: 'Appointment created successfully',
        appointment: {
          idappointment: result.insertId,
          idpatient,
          iddentist,
          idservice,
          date,
          status,
          notes,
        },
      });
    }
  );
});

app.delete('/api/app/appointments/:id', (req, res) => { 
  const idappointment = req.params.id;

  if (!idappointment) {
    return res.status(400).json({ message: 'Appointment ID is required' });
  }

  const query = 'DELETE FROM appointment WHERE idappointment = ?';

  db.query(query, [idappointment], (err, results) => {
    if (err) {
      return res.status(500).json({
        message: 'Error deleting appointment',
        error: err.message,
      });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    res.status(200).json({ message: 'Appointment deleted successfully' });
  });
});
app.get('/api/app/patients', (req, res) => {
  const query = 'SELECT * FROM users WHERE usertype = "patient"';

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching patients', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'No patients found' });
    }

    res.status(200).json({ patients: results });
  });
});

app.get('/api/app/appointmentsrecord/:idpatient', (req, res) => {
  const idpatient = req.params.idpatient;

  const query = `
    SELECT 
      a.idappointment, a.notes, 
      s.price AS service_price
    FROM appointment a
    JOIN service s ON a.idservice = s.idservice
    WHERE a.idpatient = ? AND a.status = 'D'
  `;

  db.query(query, [idpatient], (err, results) => {
    if (err) return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
    if (results.length === 0) return res.status(404).json({ message: 'No completed appointments found' });

    // Make sure the response structure matches what the frontend expects
    res.status(200).json({
      appointments: results.map((appointment) => ({
        idappointment: appointment.idappointment,
        notes: appointment.notes,
        service_price: appointment.service_price, // Return service_price as expected
      }))
    });
  });
});

app.get('/api/app/summary', (req, res) => {
  const query = `
    SELECT 
      COUNT(CASE WHEN status = 'N' THEN 1 END) AS total_appointments,
      COUNT(CASE WHEN status = 'D' THEN 1 END) AS total_clinic_visits
    FROM appointment
  `;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching summary', error: err.message });
    }

    res.status(200).json({
      total_appointments: results[0].total_appointments,
      total_clinic_visits: results[0].total_clinic_visits,
    });
  });
});


app.get('/api/app/dentists', (req, res) => {
  const query = 'SELECT idUsers, firstname, lastname FROM users WHERE usertype = "dentist"';

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching dentists', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'No dentists found' });
    }

    // Add a 'name' property to each dentist by combining firstname and lastname
    const dentistsWithNames = results.map(dentist => ({
      ...dentist,
      name: `${dentist.firstname} ${dentist.lastname}`, // Combine firstname and lastname
    }));

    res.status(200).json({ dentists: dentistsWithNames });
  });
});
app.get('/api/app/patients', (req, res) => {
  const query = 'SELECT idUsers, firstname, lastname FROM users WHERE usertype = "patient"';

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching patients', error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'No patients found' });
    }

    // Add a 'name' property to each patient by combining firstname and lastname
    const patientsWithNames = results.map(patient => ({
      ...patient,
      name: `${patient.firstname} ${patient.lastname}`, // Combine firstname and lastname
    }));

    res.status(200).json({ patients: patientsWithNames });
  });
});


  // Get All Appointments Data
  app.get('/api/app/appointments', (req, res) => {
    const query = 'SELECT * FROM appointment';

    db.query(query, (err, results) => {
      if (err) return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
      if (results.length === 0) return res.status(404).json({ message: 'No appointments found' });

      // Return all appointment data
      res.status(200).json({ appointments: results });
    });
  });



// Start the Server
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});
