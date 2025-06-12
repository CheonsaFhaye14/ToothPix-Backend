require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const cron = require('node-cron');
const app = express();
const PORT = process.env.APP_API_PORT || 3000;

// CORS configuration
const allowedOrigins = [
  process.env.FRONTEND_URL,           // e.g., https://example1.com
  process.env.SECOND_FRONTEND_URL     // e.g., https://example2.com
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
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
const admin = require('firebase-admin');
const serviceAccount = require('./service-account.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
async function sendNotificationToUser(fcmToken, message) {
  try {
    await admin.messaging().send({
      token: fcmToken,
      notification: {
        title: message.title,
        body: message.body,
      },
    });
    console.log('Notification sent');
  } catch (error) {
    console.error('Error sending notification:', error);
  }
}


cron.schedule('*/5 * * * *', async () => {
  const now = new Date();
  const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);
  const oneDayLater = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  // Query DB for appointments exactly one hour later or one day later

  const appointmentsToNotify = await getAppointmentsAtTimes([oneHourLater, oneDayLater]);

  for (const appt of appointmentsToNotify) {
    const token = await getUserFcmToken(appt.userId);
    if (token) {
      await sendNotificationToUser(token, {
        title: 'Upcoming appointment',
        body: `Your appointment is scheduled at ${appt.date} ${appt.time}`,
      });
    }
  }
});


app.post("/api/app/register", async (req, res) => {
  const { username, email, password, usertype, firstname, lastname } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!username || !email || !password || !usertype || !firstname || !lastname) {
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
      `INSERT INTO users (username, email, password, usertype, firstname, lastname)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [username, email, hashedPassword, usertype, firstname, lastname]
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




//  for logging in
app.post('/api/website/login', [
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
      { expiresIn: '24h' }
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

app.get('/api/admin', async (req, res) => {
  const query = "SELECT idUsers, email, username FROM users WHERE usertype = 'admin'";

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No admin found' });
    }

    res.status(200).json({
      admin: result.rows
    });
  } catch (err) {
    console.error('Error fetching admin:', err.message);
    res.status(500).json({ message: 'Error fetching admin', error: err.message });
  }
});

app.post('/api/app/appointments', async (req, res) => {
  const { idpatient, iddentist, date, status, notes, idservice } = req.body;

  if (!idpatient || !iddentist || !date || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({ message: 'idpatient, iddentist, date, and idservice array are required.' });
  }

  try {
    // 1. Insert appointment without services first
    const appointmentInsertQuery = `
      INSERT INTO appointment (idpatient, iddentist, date, status, notes)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING idappointment, idpatient, iddentist, date, status, notes
    `;
    const appointmentResult = await pool.query(appointmentInsertQuery, [idpatient, iddentist, date, status || 'pending', notes || '']);
    const appointment = appointmentResult.rows[0];

    // 2. Insert into appointment_services for each service ID
    const serviceInsertPromises = idservice.map(serviceId => {
      const insertQuery = `INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)`;
      return pool.query(insertQuery, [appointment.idappointment, serviceId]);
    });
    await Promise.all(serviceInsertPromises);

    // 3. Return success with appointment info (you might want to add services on response later)
    res.status(201).json({
      message: 'Appointment created successfully',
      appointment,
    });

  } catch (err) {
    console.error('Error creating appointment:', err.message);
    res.status(500).json({ message: 'Error creating appointment', error: err.message });
  }
});

app.post('/api/website/appointments', async (req, res) => {
  const { idpatient, iddentist, date, status, notes, idservice, patient_name } = req.body;

  // Validate required fields
  if ((!idpatient && !patient_name) || !iddentist || !date || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({
      message: 'If idpatient is not provided, patient_name is required. Also, iddentist, date, and idservice array are required.'
    });
  }

  try {
    let insertQuery, insertValues;

    if (idpatient) {
      // For registered users
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, NULL AS patient_name
      `;
      insertValues = [idpatient, iddentist, date, status || 'pending', notes || ''];
    } else {
      // For non-users / walk-ins
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes, patient_name)
        VALUES (NULL, $1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      insertValues = [iddentist, date, status || 'pending', notes || '', patient_name];
    }

    const appointmentResult = await pool.query(insertQuery, insertValues);
    const appointment = appointmentResult.rows[0];

    // Insert appointment_services
    const serviceInsertPromises = idservice.map(serviceId => {
      const insertServiceQuery = `
        INSERT INTO appointment_services (idappointment, idservice)
        VALUES ($1, $2)
      `;
      return pool.query(insertServiceQuery, [appointment.idappointment, serviceId]);
    });
    await Promise.all(serviceInsertPromises);

    res.status(201).json({
      message: 'Appointment created successfully',
      appointment,
    });

  } catch (err) {
    console.error('Error creating appointment:', err.message);
    res.status(500).json({ message: 'Error creating appointment', error: err.message });
  }
});
app.get('/api/website/report/patients', async (req, res) => {
  try {
    const query = `
      SELECT  
        p.idusers             AS patient_id,
        CONCAT(p.firstname, ' ', p.lastname) AS patient_name,
        p.birthdate,
        p.gender,
        a.date                AS appointment_date,
        STRING_AGG(DISTINCT s.name, ', ')    AS services,
        r.treatment_notes,
        CONCAT(d.firstname, ' ', d.lastname) AS doctor_name,
        SUM(s.price)         AS total_amount
      FROM users p
      LEFT JOIN appointment a 
        ON a.idpatient = p.idusers
        AND a.status = 'completed'        -- only “completed” appointments
      LEFT JOIN users d 
        ON a.iddentist = d.idusers
      LEFT JOIN records r 
        ON r.idappointment = a.idappointment
      LEFT JOIN appointment_services aps 
        ON aps.idappointment = a.idappointment
      LEFT JOIN service s 
        ON aps.idservice = s.idservice
      WHERE p.usertype = 'patient'
        AND a.idappointment IS NOT NULL    -- exclude rows where no completed appointment exists
      GROUP BY 
        p.idusers, p.firstname, p.lastname, p.birthdate, p.gender,
        a.idappointment, a.date, d.firstname, d.lastname, r.treatment_notes
      ORDER BY patient_name ASC, appointment_date ASC;
    `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching all patient data:', err);
    res.status(500).json({ message: 'Server error' });
  }
});



app.get('/api/app/patientrecords/:id', async (req, res) => {
  const patientId = req.params.id;

  const query = `
    SELECT 
      r.idrecord,
      r.idappointment,
      r.iddentist,
      CONCAT(d.firstname, ' ', d.lastname) AS dentistFullname,
      a.date AS appointmentDate,
      r.paymentstatus,
      r.treatment_notes,
      COALESCE(
        (
          SELECT STRING_AGG(s.name || ' ' || s.price,  ', ' )  -- Concatenate service name and price
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), ''
      ) AS servicesWithPrices,
      COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) AS totalPrice,
      COALESCE(r.total_paid, 0) AS totalPaid,
      (COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) - COALESCE(r.total_paid, 0)) AS stillOwe  -- Calculate the remaining balance
    FROM records r
    LEFT JOIN users d ON r.iddentist = d.idusers
    LEFT JOIN appointment a ON r.idappointment = a.idappointment
    WHERE r.idpatient = $1
    ORDER BY r.idrecord DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query, [patientId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found for this patient' });
    }

    res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching patient records:', err.message);
    res.status(500).json({ message: 'Error fetching patient records', error: err.message });
  }
});


cron.schedule('*/5 * * * *', async () => { // every 5 minutes
  try {
    await pool.query(`
      UPDATE appointment
      SET status = 'completed'
      WHERE date < NOW()
        AND status NOT IN ('cancelled', 'completed')
    `);
    console.log('Appointment statuses updated.');
  } catch (err) {
    console.error('Scheduled update failed:', err.message);
  }
});



app.get('/api/app/dentistrecords/:id', async (req, res) => { 
  const dentistId = req.params.id;

  const query = `
    SELECT 
      r.idrecord,
      r.idappointment,
      r.idpatient,
      CONCAT(p.firstname, ' ', p.lastname) AS patientFullname,  -- Patient's full name
      a.patient_name AS patientName,  -- Fallback to patient_name from appointment (optional)
      a.date AS appointmentDate,  -- Appointment date
      r.paymentstatus,  -- Payment status
      r.treatment_notes,  -- Treatment notes
      COALESCE(
        (
          SELECT STRING_AGG(s.name || ' ' || s.price, ', ')  -- Concatenate service name and price
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), ''
      ) AS servicesWithPrices,  -- List of services with their respective prices
      COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) AS totalPrice,  -- Total price of all services in this appointment
      COALESCE(r.total_paid, 0) AS totalPaid,  -- Total amount paid by the patient
      (COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) - COALESCE(r.total_paid, 0)) AS stillOwe  -- Calculate the remaining balance
    FROM records r
    LEFT JOIN users p ON r.idpatient = p.idusers  -- Join with patient table
    LEFT JOIN appointment a ON r.idappointment = a.idappointment  -- Join with appointment table
    WHERE r.iddentist = $1  -- Dentist ID (parameterized query)
    ORDER BY r.idrecord DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query, [dentistId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found for this dentist' });
    }

    res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching dentist records:', err.message);
    res.status(500).json({ message: 'Error fetching dentist records', error: err.message });
  }
});

app.post('/api/website/record', async (req, res) => {
  const { idpatient, patient_name, iddentist, date, services, treatment_notes } = req.body;

  if (!iddentist || !date || !Array.isArray(services) || services.length === 0) {
    return res.status(400).json({ message: 'Missing or invalid dentist, date, or services.' });
  }

  if (!idpatient && !patient_name) {
    return res.status(400).json({ message: 'Either idpatient or patient_name is required.' });
  }

  try {
    await pool.query('BEGIN');

    // 1. Insert appointment with status = 'completed'
    let insertAppointmentQuery, insertParams;

    if (idpatient) {
      insertAppointmentQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, notes, patient_name, status)
        VALUES ($1, $2, $3, $4, NULL, 'completed')
        RETURNING idappointment
      `;
      insertParams = [idpatient, iddentist, date, ''];
    } else {
      insertAppointmentQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, notes, patient_name, status)
        VALUES (NULL, $1, $2, $3, $4, 'completed')
        RETURNING idappointment
      `;
      insertParams = [iddentist, date, '', patient_name];
    }

    const apptResult = await pool.query(insertAppointmentQuery, insertParams);
    const idappointment = apptResult.rows[0].idappointment;

    // 2. Insert appointment services
    for (const idservice of services) {
      await pool.query(
        `INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)`,
        [idappointment, idservice]
      );
    }

    // 3. Insert record if treatment_notes provided
    if (treatment_notes !== undefined && treatment_notes.trim() !== '') {
      const apptDetails = await pool.query(
        `SELECT idpatient, iddentist FROM appointment WHERE idappointment = $1`,
        [idappointment]
      );

      const { idpatient: patientIdFromAppt, iddentist: dentistIdFromAppt } = apptDetails.rows[0];

      await pool.query(
        `INSERT INTO records (idpatient, iddentist, idappointment, treatment_notes)
         VALUES ($1, $2, $3, $4)`,
        [patientIdFromAppt, dentistIdFromAppt, idappointment, treatment_notes]
      );
    }

    await pool.query('COMMIT');
    res.status(201).json({ message: 'Appointment and record created successfully.', idappointment });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error creating appointment and record:', error.message);
    res.status(500).json({ message: 'Failed to create appointment and record.', error: error.message });
  }
});

app.put('/api/app/appointmentstatus/:id', async (req, res) => {
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

app.put('/api/website/record/:idappointment', async (req, res) => {
  const { idappointment } = req.params;
  const { iddentist, date, services, treatment_notes } = req.body;

  if (!iddentist || !date || !Array.isArray(services)) {
    return res.status(400).json({ message: 'Missing or invalid dentist, date, or services.' });
  }

  try {
    await pool.query('BEGIN');

    // Update dentist and date
    const updateAppointmentQuery = `
      UPDATE appointment
      SET iddentist = $1, date = $2
      WHERE idappointment = $3
      RETURNING *;
    `;
    const updateResult = await pool.query(updateAppointmentQuery, [iddentist, date, idappointment]);

    if (updateResult.rowCount === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ message: 'Appointment not found.' });
    }

    // Get current services for this appointment
    const currentServicesResult = await pool.query(
      `SELECT idservice FROM appointment_services WHERE idappointment = $1`,
      [idappointment]
    );
    const currentServiceIds = currentServicesResult.rows.map(row => row.idservice);

    const newServiceIds = [...new Set(services)];

    const servicesToAdd = newServiceIds.filter(id => !currentServiceIds.includes(id));
    const servicesToRemove = currentServiceIds.filter(id => !newServiceIds.includes(id));

    // Delete removed services
    for (const idservice of servicesToRemove) {
      await pool.query(
        `DELETE FROM appointment_services WHERE idappointment = $1 AND idservice = $2`,
        [idappointment, idservice]
      );
    }

    // Insert new services
    for (const idservice of servicesToAdd) {
      await pool.query(
        `INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)`,
        [idappointment, idservice]
      );
    }

    // Update or insert treatment notes
    if (treatment_notes !== undefined) {
      const recordCheck = await pool.query(
        `SELECT idrecord FROM records WHERE idappointment = $1`,
        [idappointment]
      );

      if (recordCheck.rowCount > 0) {
        await pool.query(
          `UPDATE records SET treatment_notes = $1 WHERE idappointment = $2`,
          [treatment_notes, idappointment]
        );
      } else {
        const apptRes = await pool.query(
          `SELECT idpatient, iddentist FROM appointment WHERE idappointment = $1`,
          [idappointment]
        );
        if (apptRes.rowCount === 0) {
          await pool.query('ROLLBACK');
          return res.status(404).json({ message: 'Appointment not found when creating record.' });
        }
        const { idpatient, iddentist: dentistIdFromAppt } = apptRes.rows[0];

        await pool.query(
          `INSERT INTO records (idpatient, iddentist, idappointment, treatment_notes)
           VALUES ($1, $2, $3, $4)`,
          [idpatient, dentistIdFromAppt, idappointment, treatment_notes]
        );
      }
    }

    await pool.query('COMMIT');
    res.status(200).json({ message: 'Appointment updated successfully.' });
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('Error updating appointment:', err.message);
    res.status(500).json({ message: 'Failed to update appointment', error: err.message });
  }
});

app.delete('/api/website/record/:id', async (req, res) => {
  const id = req.params.id;

  try {
    // Delete the appointment record from your tables
    // Note: you might need to delete from related tables (like appointment_services or records) based on your DB schema
    // Here, let's assume you want to delete from appointment table, which cascades to related tables or handle manually

    // For example, if you have FK with cascade delete, this will work:
    const deleteQuery = `DELETE FROM appointment WHERE idappointment = $1`;
    const result = await pool.query(deleteQuery, [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    res.status(200).json({ message: 'Appointment deleted successfully' });
  } catch (error) {
    console.error('Error deleting appointment:', error.message);
    res.status(500).json({ message: 'Error deleting appointment', error: error.message });
  }
});

app.delete('/api/app/appointments/:id', async (req, res) => {
  const appointmentId = parseInt(req.params.id, 10);

  if (isNaN(appointmentId)) {
    return res.status(400).json({ message: 'Invalid appointment ID' });
  }

  console.log('Deleting appointment with id:', appointmentId, 'type:', typeof appointmentId);

  const query = 'DELETE FROM appointment WHERE idappointment = $1';

  try {
    const result = await pool.query(query, [appointmentId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    res.status(200).json({ message: 'Appointment deleted successfully' });
  } catch (err) {
    console.error('Error deleting, appointment in use:', err);
    res.status(500).json({ message: 'Error deleting, appointment in use', error: err.message });
  }
});

app.get('/api/website/record', async (req, res) => {
  const query = `
WITH appointment_info AS (
  SELECT
    a.idappointment,
    a.date,
    COALESCE(NULLIF(CONCAT(p.firstname, ' ', p.lastname), ' '), a.patient_name) AS patient_name,
    CONCAT(d.firstname, ' ', d.lastname) AS dentist_name
  FROM appointment a
  LEFT JOIN users p ON a.idpatient = p.idusers
  JOIN users d ON a.iddentist = d.idusers
)
SELECT
  ai.idappointment,
  ai.date,
  ai.patient_name,
  ai.dentist_name,
  STRING_AGG(s.name, ', ') AS services,
  SUM(s.price) AS total_price,
  r.treatment_notes
FROM appointment_info ai
JOIN appointment_services aps ON ai.idappointment = aps.idappointment
JOIN service s ON aps.idservice = s.idservice
LEFT JOIN records r ON r.idappointment = ai.idappointment
GROUP BY
  ai.idappointment,
  ai.date,
  ai.patient_name,
  ai.dentist_name,
  r.treatment_notes
ORDER BY ai.date ASC;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No past appointments found' });
    }

    res.status(200).json({
      records: result.rows
    });
  } catch (err) {
    console.error('Error fetching records:', err.message);
    res.status(500).json({ message: 'Error fetching records', error: err.message });
  }
});


app.get('/api/website/payment', async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // STEP 1: Insert missing records for past appointments
    const insertMissingRecordsQuery = `
      INSERT INTO records (idpatient, iddentist, idappointment)
      SELECT a.idpatient, a.iddentist, a.idappointment
      FROM appointment a
      LEFT JOIN records r ON r.idappointment = a.idappointment
      WHERE a.date < NOW() AT TIME ZONE 'Asia/Manila'
        AND r.idappointment IS NULL;
    `;
    await client.query(insertMissingRecordsQuery);

    // STEP 2: Fetch payment-related appointment data
    const paymentQuery = `
      SELECT
        a.idappointment,
        a.date,
        CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,
        COALESCE(NULLIF(CONCAT(p.firstname, ' ', p.lastname), ' '), a.patient_name) AS patient_name,
        STRING_AGG(s.name || ' ' || s.price, ', ') AS services_with_prices,
        SUM(s.price) AS total_price,
        r.paymentstatus,
        r.total_paid,
        (SUM(s.price) - r.total_paid) AS still_owe
      FROM appointment a
      LEFT JOIN users p ON a.idpatient = p.idusers
      JOIN users d ON a.iddentist = d.idusers
      JOIN appointment_services aps ON a.idappointment = aps.idappointment
      JOIN service s ON aps.idservice = s.idservice
      JOIN records r ON r.idappointment = a.idappointment
      WHERE a.date < NOW() AT TIME ZONE 'Asia/Manila'
      GROUP BY 
        a.idappointment, 
        a.date, 
        CONCAT(d.firstname, ' ', d.lastname),
        COALESCE(NULLIF(CONCAT(p.firstname, ' ', p.lastname), ' '), a.patient_name),
        r.paymentstatus, 
        r.total_paid
      ORDER BY a.date DESC;
    `;

    const result = await client.query(paymentQuery);

    await client.query('COMMIT');

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No payment records found' });
    }

    res.status(200).json({
      payments: result.rows
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error in payment API:', err.message);
    res.status(500).json({ message: 'Error fetching payments', error: err.message });
  } finally {
    client.release();
  }
});

app.put('/api/website/payment/:id', async (req, res) => {
  const { id } = req.params;
  const { total_paid, total_price } = req.body;

  if (isNaN(total_paid) || total_paid < 0) {
    return res.status(400).json({ message: 'Invalid total_paid amount' });
  }

  if (isNaN(total_price) || total_price <= 0) {
    return res.status(400).json({ message: 'Invalid total_price amount' });
  }

  // ✅ Updated logic for payment status
  let paymentstatus;
  if (parseFloat(total_paid) === 0) {
    paymentstatus = 'unpaid';
  } else if (parseFloat(total_paid) < parseFloat(total_price)) {
    paymentstatus = 'partial';
  } else {
    paymentstatus = 'paid';
  }

  const client = await pool.connect();

  try {
    const updateQuery = `
      UPDATE records
      SET total_paid = $1,
          paymentstatus = $2
      WHERE idappointment = $3
      RETURNING *;
    `;

    const result = await client.query(updateQuery, [total_paid, paymentstatus, id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found or not eligible for update' });
    }

    res.status(200).json({
      message: 'Payment updated successfully',
      updatedRecord: result.rows[0],
    });
  } catch (err) {
    console.error('Error updating payment:', err.message);
    res.status(500).json({ message: 'Failed to update payment', error: err.message });
  } finally {
    client.release();
  }
});

app.get('/appointment-services/:idappointment', async (req, res) => {
  const { idappointment } = req.params;

  try {
    const result = await pool.query(
      `SELECT s.idservice, s.name, s.price
       FROM appointment_services aps
       JOIN service s ON aps.idservice = s.idservice
       WHERE aps.idappointment = $1`,
      [idappointment]
    );

    const services = result.rows; // contains idservice, name, and price
    res.json({ services });
  } catch (error) {
    console.error('Error fetching services for appointment:', error.message);
    res.status(500).json({ error: 'Error fetching services for appointment' });
  }
});






app.put('/api/app/users/:id', async (req, res) => {
  const userId = req.params.id;
  const {
    username,
    email,
    password,
    usertype,
    firstname,
    lastname,
    birthdate,
    contact,
    address,
    gender,
    allergies,
    medicalhistory
  } = req.body;

  if (!username || !email || !firstname || !lastname || !usertype) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  const validUsertypes = ['patient', 'dentist', 'admin'];
  if (!validUsertypes.includes(usertype.toLowerCase())) {
    return res.status(400).json({ message: 'Invalid usertype. Must be patient, dentist, or admin.' });
  }

  try {
    // Check if user exists
    const userResult = await pool.query('SELECT * FROM users WHERE idusers = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if username already exists for another user
    const usernameCheck = await pool.query(
  'SELECT * FROM users WHERE username = $1 AND idusers != $2',
  [username, userId]
);
    if (usernameCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username already exists' });
    }

  // Check if email already exists for another user
const emailCheck = await pool.query(
  'SELECT * FROM users WHERE email = $1 AND idusers != $2',
  [email, userId]
);
    if (emailCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const existingUser = userResult.rows[0];
    let hashedPassword = existingUser.password;

    // Only re-hash if password is changed
    if (password && !(await bcrypt.compare(password, existingUser.password))) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    // Update user record
const updateQuery = `
  UPDATE users
  SET username = $1,
      email = $2,
      password = $3,
      usertype = $4,
      firstname = $5,
      lastname = $6,
      birthdate = $7,
      contact = $8,
      address = $9,
      gender = $10,
      allergies = $11,
      medicalhistory = $12
  WHERE idusers = $13
  RETURNING *;
`;

    const values = [
      username,
      email,
      hashedPassword,
      usertype.toLowerCase(),
      firstname,
      lastname,
      birthdate,
      contact,
      address,
      gender,
      allergies,
      medicalhistory,
      userId,
    ];

    const result = await pool.query(updateQuery, values);

    res.status(200).json({
      message: 'User updated successfully',
      user: result.rows[0],
    });

  } catch (error) {
    console.error('Error updating user:', error.message);
    res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});

app.get('/api/app/records', async (req, res) => {
 const query = `
  SELECT 
    p.idusers AS idpatient, -- ✅ Add patient ID here
    r.idrecord,
    CONCAT(p.firstname, ' ', p.lastname) AS patientFullname,
    CONCAT(d.firstname, ' ', d.lastname) AS dentistFullname,
    r.treatment_notes,
    r.paymentstatus,
    r.idappointment,
    a.date AS appointmentDate,
    COALESCE(
      (
        SELECT STRING_AGG(s.name, ', ')
        FROM appointment_services aps
        JOIN service s ON aps.idservice = s.idservice
        WHERE aps.idappointment = r.idappointment
      ), ''
    ) AS services,
    COALESCE(
      (
        SELECT SUM(s.price)
        FROM appointment_services aps
        JOIN service s ON aps.idservice = s.idservice
        WHERE aps.idappointment = r.idappointment
      ), 0
    ) AS totalPrice
  FROM users p
  LEFT JOIN records r ON r.idpatient = p.idusers
  LEFT JOIN users d ON r.iddentist = d.idusers
  LEFT JOIN appointment a ON r.idappointment = a.idappointment
  WHERE p.usertype = 'patient'
  ORDER BY r.idrecord DESC NULLS LAST;
`;


  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

    res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching records:', err.message);
    res.status(500).json({ message: 'Error fetching records', error: err.message });
  }
});

 
app.post('/api/app/users', async (req, res) => {
  const {
    username,
    email,
    password,
    usertype,
    firstname,
    lastname,
    birthdate,
    contact,
    address,
    gender,
    allergies,
    medicalhistory
  } = req.body;

  // Basic validation
  if (!username || !email || !password || !usertype || !firstname || !lastname) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  try {
    // Check if username or email already exists
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (userCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // ✅ Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10); // 10 = salt rounds

    // Insert new user with hashed password
    const insertQuery = `
      INSERT INTO users (
        username, email, password, usertype, firstname, lastname,
        birthdate, contact, address, gender, allergies, medicalhistory
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *;
    `;

    const values = [
      username,
      email,
      hashedPassword, // ✅ Use hashed password here
      usertype,
      firstname,
      lastname,
      birthdate,
      contact,
      address,
      gender,
      allergies,
      medicalhistory,
    ];

    const result = await pool.query(insertQuery, values);

    res.status(201).json({
      message: 'User created successfully',
      user: result.rows[0],
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ message: 'Username or email already exists' });
    }
    console.error('Error adding user:', error.message);
    res.status(500).json({ message: 'Error adding user', error: error.message });
  }
});


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


// Request password reset endpoint
app.post('/api/request-reset-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Step 1: Check if user exists and if reset token is already active
    const checkQuery = 'SELECT reset_token, reset_token_expiry FROM users WHERE email = $1';
    const checkResult = await pool.query(checkQuery, [email]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ message: `No user found with email: ${email}` });
    }

    const user = checkResult.rows[0];

    // Step 2: Prevent duplicate reset if token is still valid
    if (user.reset_token && user.reset_token_expiry > new Date()) {
      return res.status(429).json({
        message: 'A reset link was already sent recently. Please check your email or try again later.',
        validUntil: user.reset_token_expiry
      });
    }

    // Step 3: Generate new token
    const token = crypto.randomBytes(20).toString('hex');
    const expiration = new Date(Date.now() + 3600000); // 1 hour

    const updateQuery = 'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3';
    await pool.query(updateQuery, [token, expiration, email]);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetLink = `https://cheonsafhaye14.github.io/ToothPix-website/#/resetpassword?token=${token}`;

    try {
      await transporter.sendMail({
        to: email,
        subject: 'Password Reset Request',
        text: `Click the following link to reset your password: ${resetLink}`,
      });

      res.status(200).json({ message: `Password reset link sent to ${email}.` });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      return res.status(500).json({ message: 'Failed to send email', error: emailError.message });
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ message: 'Database error occurred', error: err.message });
  }
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }

  try {
    const userQuery = 'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()';
    const userResult = await pool.query(userQuery, [token]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired reset token. Please request a new one.' });
    }

    const user = userResult.rows[0]; // get user info including usertype

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const updateQuery = `
      UPDATE users
      SET password = $1, reset_token = NULL, reset_token_expiry = NULL
      WHERE reset_token = $2
    `;
    await pool.query(updateQuery, [hashedPassword, token]);

    // Return success message + usertype
    res.status(200).json({ 
      message: 'Password has been successfully reset. You can now log in with your new password.', 
      usertype: user.usertype 
    });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ message: 'Server error during password reset', error: err.message });
  }
});



app.post('/api/app/records', async (req, res) => {
  const { idpatient, iddentist, idappointment, treatment_notes, paymentstatus } = req.body;

  if (!idpatient || !iddentist || !idappointment) {
    return res.status(400).json({ message: 'idpatient, iddentist, and idappointment are required.' });
  }

  try {
    // Check if a record already exists for this idappointment
    const existing = await pool.query(
      'SELECT 1 FROM records WHERE idappointment = $1',
      [idappointment]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ message: 'A record for this appointment already exists.' });
    }

    // Insert new record
    const query = `
      INSERT INTO records (idpatient, iddentist, idappointment, treatment_notes, paymentstatus)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING idrecord, idpatient, iddentist, idappointment, treatment_notes, paymentstatus
    `;

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
// app.get('/api/app/records', async (req, res) => {
//   const query = 'SELECT * FROM records';

//   try {
//     const result = await pool.query(query);

//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: 'No records found' });
//     }

//     res.status(200).json({
//       records: result.rows
//     });
//   } catch (err) {
//     console.error('Error fetching records:', err.message);
//     res.status(500).json({ message: 'Error fetching records', error: err.message });
//   }
// });

// Get all users
app.get('/api/app/users', async (req, res) => {
  const query = 'SELECT * FROM users';

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    res.status(200).json({
      records: result.rows
    });
  } catch (err) {
    console.error('Error fetching users:', err.message);
    res.status(500).json({ message: 'Error fetching users', error: err.message });
  }
});

// // Update a record
// app.put('/api/app/records/:id', async (req, res) => {
//   const id = req.params.id;
//   const { treatment_notes, paymentstatus } = req.body;

//   // Validate input
//   const allowedStatuses = ['paid', 'unpaid', 'partial'];
//   if (paymentstatus && !allowedStatuses.includes(paymentstatus)) {
//     return res.status(400).json({ message: 'Invalid payment status' });
//   }

//   const query = `
//     UPDATE records 
//     SET treatment_notes = $1, paymentstatus = $2
//     WHERE idrecord = $3
//     RETURNING idrecord, idpatient, iddentist, idappointment, treatment_notes, paymentstatus
//   `;

//   try {
//     const result = await pool.query(query, [treatment_notes, paymentstatus, id]);

//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: 'Record not found' });
//     }

//     const updatedRecord = result.rows[0];

//     res.status(200).json({
//       message: 'Record updated successfully',
//       record: updatedRecord,
//     });
//   } catch (err) {
//     console.error('Error updating record:', err.message);
//     res.status(500).json({ message: 'Error updating record', error: err.message });
//   }
// });

app.put('/api/app/records/:idrecord', async (req, res) => {
  const { idrecord } = req.params;
  const { treatment_notes, paymentstatus } = req.body;

  if (!idrecord) {
    return res.status(400).json({ message: 'idrecord is required.' });
  }

  try {
    const result = await pool.query(
      `UPDATE records
       SET treatment_notes = $1,
           paymentstatus = $2
       WHERE idrecord = $3
       RETURNING *`,
      [treatment_notes, paymentstatus, idrecord]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Record not found.' });
    }

    res.json({
      message: 'Record updated successfully',
      record: result.rows[0],
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
    console.error('Error deleting, record in use:', err.message);
    res.status(500).json({ message: 'Error deleting, record in use', error: err.message });
  }
});

//app
// app.put('/api/app/appointments/:id', async (req, res) => {
//   const id = req.params.id;
//   const { status, notes, date } = req.body;

//   // Supported statuses
//   const allowedStatuses = ['approved', 'cancelled', 'rescheduled', 'declined'];

//   // Validate status
//   if (!status || !allowedStatuses.includes(status)) {
//     return res.status(400).json({ message: 'Invalid or missing status' });
//   }

//   // Auto-generate notes if not provided
//   const now = new Date();
  
//   // Format the date as "YYYY-MM-DD HH:mm"
//   const formattedDate = now.toISOString().slice(0, 16).replace("T", " "); // e.g., "2025-05-04 21:42"

//   let finalNotes = notes;

//   if (!notes) {
//     if (status === 'approved') {
//       finalNotes = `Approved by dentist on ${formattedDate}`;
//     } else if (status === 'declined' || status === 'cancelled') {
//       finalNotes = `Cancelled by dentist on ${formattedDate}. Please reschedule.`;
//     } else if (status === 'rescheduled' && date) {
//       finalNotes = `Rescheduled to ${date}`;
//     }
//   }

//   // Initialize query components
//   const setValues = [];
//   const queryParams = [];
//   let query = 'UPDATE appointment SET ';

//   // Set fields to update
//   if (status) {
//     setValues.push(`status = $${setValues.length + 1}`);
//     queryParams.push(status);
//   }

//   if (finalNotes !== undefined) {
//     setValues.push(`notes = $${setValues.length + 1}`);
//     queryParams.push(finalNotes);
//   }

//   if (date && !isNaN(Date.parse(date))) {
//     setValues.push(`date = $${setValues.length + 1}`);
//     queryParams.push(date);
//   }

//   if (setValues.length === 0) {
//     return res.status(400).json({ message: 'No valid fields to update' });
//   }

//   // Build final SQL query
//   query += setValues.join(', ');
//   query += ` WHERE idappointment = $${setValues.length + 1} RETURNING *`;
//   queryParams.push(id);

//   try {
//     const result = await pool.query(query, queryParams);

//     if (result.rowCount === 0) {
//       return res.status(404).json({ message: 'Appointment not found.' });
//     }

//     res.json({
//       message: 'Appointment updated successfully',
//       appointment: result.rows[0],
//     });
//   } catch (err) {
//     console.error('Error updating appointment:', err.message);
//     res.status(500).json({
//       message: 'Error updating appointment',
//       error: err.message,
//     });
//   }
// });

app.put('/api/app/appointments/:id', async (req, res) => {
  const idappointment = req.params.id;
  const { idpatient, iddentist, date, status, notes, idservice, patient_name } = req.body;

  // Validate iddentist and idservice array presence
  if (!iddentist || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({ message: 'iddentist and idservice array are required.' });
  }

  // Validate either idpatient or patient_name is provided (at least one)
  if (!idpatient && !patient_name) {
    return res.status(400).json({ message: 'Either idpatient or patient_name is required.' });
  }

  try {
    // 1. Fetch existing appointment date if `date` is not provided
    let finalDate = date;
    if (!date) {
      const existing = await pool.query('SELECT date FROM appointment WHERE idappointment = $1', [idappointment]);
      if (existing.rows.length === 0) {
        return res.status(404).json({ message: 'Appointment not found' });
      }
      finalDate = existing.rows[0].date;
    }

    // 2. Update appointment

    // Different queries depending on presence of idpatient or patient_name
    let updateAppointmentQuery;
    let queryParams;

    if (idpatient) {
      // Registered patient update (patient_name set to NULL)
      updateAppointmentQuery = `
        UPDATE appointment
        SET idpatient = $1, iddentist = $2, date = $3, status = $4, notes = $5, patient_name = NULL
        WHERE idappointment = $6
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      queryParams = [idpatient, iddentist, finalDate, status || 'pending', notes || '', idappointment];
    } else {
      // Walk-in update (idpatient set to NULL)
      updateAppointmentQuery = `
        UPDATE appointment
        SET idpatient = NULL, iddentist = $1, date = $2, status = $3, notes = $4, patient_name = $5
        WHERE idappointment = $6
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      queryParams = [iddentist, finalDate, status || 'pending', notes || '', patient_name, idappointment];
    }

    const result = await pool.query(updateAppointmentQuery, queryParams);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    const updatedAppointment = result.rows[0];

    // 3. Replace appointment services
    await pool.query('DELETE FROM appointment_services WHERE idappointment = $1', [idappointment]);

    const insertServicePromises = idservice.map(serviceId =>
      pool.query('INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)', [idappointment, serviceId])
    );
    await Promise.all(insertServicePromises);

    // 4. Respond with success
    res.json({
      message: 'Appointment updated successfully',
      appointment: updatedAppointment,
    });

  } catch (error) {
    console.error('Error updating appointment:', error.message);
    res.status(500).json({ message: 'Error updating appointment', error: error.message });
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

// // ✅ Create a new appointment //app
// app.post('/api/app/appointments', async (req, res) => {
//   const { idpatient, iddentist, date, status, notes, idservice } = req.body;

//   // Validate required fields
//   if (!idpatient || !iddentist || !date || !idservice) {
//     return res.status(400).json({ message: 'idpatient, iddentist, date, and idservice are required.' });
//   }

//   const query = `
//     INSERT INTO appointment (idpatient, iddentist, date, status, notes, idservice)
//     VALUES ($1, $2, $3, $4, $5, $6)
//     RETURNING idappointment, idpatient, iddentist, date, status, notes, idservice
//   `;

//   try {
//     const result = await pool.query(query, [idpatient, iddentist, date, status || 'pending', notes || '', idservice]);
//     const appointment = result.rows[0];

//     res.status(201).json({
//       message: 'Appointment created successfully',
//       appointment,
//     });
//   } catch (err) {
//     console.error('Error creating appointment:', err.message);
//     res.status(500).json({ message: 'Error creating appointment', error: err.message });
//   }
// });

app.get('/api/app/appointments', async (req, res) => {
 

  // Modify the fetchQuery to include sorting by date and then by idappointment
  const fetchQuery = 'SELECT * FROM appointment ORDER BY date ASC, idappointment ASC'; // First by date, then by idappointment

  const client = await pool.connect();

  try {
    await client.query('BEGIN'); // Start a transaction

    // Fetch all appointments, sorted by date and idappointment
    const result = await client.query(fetchQuery);

    await client.query('COMMIT'); // Commit the transaction

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    // Send the sorted appointments back in the response
    res.status(200).json({
      appointments: result.rows
    });
  } catch (err) {
    await client.query('ROLLBACK'); // Rollback in case of error
    console.error('Error fetching appointments:', err.message);
    res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  } finally {
    client.release(); // Release the client back to the pool
  }
});



// In-memory refresh token store (for demo; move to DB for production)
let refreshTokensStore = [];

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

    // Generate access token
    const accessToken = jwt.sign(
      { userId: user.idusers, username: user.username, usertype: user.usertype },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Generate refresh token (random string)
    const refreshToken = crypto.randomBytes(64).toString('hex');

    // Store refresh token associated with user id
    refreshTokensStore.push({ token: refreshToken, userId: user.idusers });

    res.status(200).json({
      message: 'Login successful',
      accessToken: accessToken,
      refreshToken: refreshToken,
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

app.post('/api/app/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.status(401).json({ message: 'Refresh token required' });

  const storedToken = refreshTokensStore.find(rt => rt.token === refreshToken);

  if (!storedToken) return res.status(403).json({ message: 'Invalid refresh token' });

  // Generate new access token for the user
  const newAccessToken = jwt.sign(
    { userId: storedToken.userId }, 
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.status(200).json({ accessToken: newAccessToken });
});
app.post('/api/app/logout', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ message: 'Refresh token required' });

  refreshTokensStore = refreshTokensStore.filter(rt => rt.token !== refreshToken);

  res.status(200).json({ message: 'Logged out successfully' });
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
  const { name, description, price, category } = req.body;

  // Validation
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }

  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }

  if (!category || typeof category !== 'string' || category.trim().length === 0) {
    return res.status(400).json({ message: 'Category is required and must be a non-empty string.' });
  }

  // Debug log
  console.log('Received data:', { name, description, price, category });

  const query = `
    INSERT INTO service (name, description, price, category)
    VALUES ($1, $2, $3, $4)
    RETURNING idservice, name, description, price, category
  `;

  try {
    const result = await pool.query(query, [
      name.trim(),
      description,
      parseFloat(price),
      category.trim()
    ]);
    const service = result.rows[0];

    console.log('Service added:', service);

    res.status(201).json({
      message: 'Service added successfully',
      service,
    });
  } catch (err) {
    console.error('Error adding service:', err.message);

    res.status(500).json({
      message: 'Error adding service',
      error: err.message,
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
    console.error('Error deleting, service in use:', err.message);
    res.status(500).json({ message: 'Error deleting, service in use', error: err.message });
  }
});
// Delete User
app.delete('/api/app/users/:id', async (req, res) => {
  const userId = req.params.id;
  const query = 'DELETE FROM users WHERE idusers = $1';

  try {
    const result = await pool.query(query, [userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting, user in use:', err.message);
    res.status(500).json({ message: 'Error deleting, user in use', error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});
