// ✅ Load environment variables from the .env file
require('dotenv').config();

// ✅ Import all required dependencies
const express = require('express');           // Main web framework for creating the backend server
const { Pool } = require('pg');               // PostgreSQL client for connecting to your database
const bcrypt = require('bcryptjs');           // Used for hashing and comparing passwords
const jwt = require('jsonwebtoken');          // Used for creating and verifying JWT tokens (for login sessions)
const bodyParser = require('body-parser');    // Parses incoming request bodies (e.g., form data or JSON)
const cors = require('cors');                 // Enables cross-origin requests (for connecting frontend and backend)
const crypto = require('crypto');             // Provides encryption and random token generation (e.g., for password reset)
const nodemailer = require('nodemailer');     // Sends emails (e.g., password reset, notifications)
const { body, validationResult } = require('express-validator'); // Used to validate input fields
const cron = require('node-cron');            // Runs scheduled background tasks (e.g., auto-delete old data)
const admin = require('firebase-admin');      // For Firebase features like notifications

// ✅ Create an Express application instance
const app = express();

// ✅ Define the server port (from .env or fallback to 3000)
const PORT = process.env.APP_API_PORT || 3000;

// List of allowed frontend URLs that can access this backend
const allowedOrigins = [
  process.env.FRONTEND_URL,          // GitHub-hosted frontend (deployed version)
  process.env.SECOND_FRONTEND_URL    // Local frontend (for development/testing)
];

// CORS (Cross-Origin Resource Sharing) options
// This controls which origins (websites) can send requests to your server
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests if origin is in the allowed list or if no origin (like from Postman)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true); // Allow the request
    } else {
      callback(new Error('Not allowed by CORS')); // Block unauthorized origins
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
};

// Apply CORS settings to the Express app
app.use(cors(corsOptions));

// Enable parsing of incoming JSON data in request bodies
app.use(bodyParser.json());

// PostgreSQL connection setup
const pool = new Pool({
  host: process.env.DB_HOST,       // The host address of your PostgreSQL server (e.g., Render or local)
  port: process.env.DB_PORT,       // The port number PostgreSQL is running on (default: 5432)
  user: process.env.DB_USER,       // The PostgreSQL username (from your Render or local DB settings)
  password: process.env.DB_PASSWORD, // The user's password
  database: process.env.DB_NAME,   // The database name you want to connect to
  ssl: {
    rejectUnauthorized: false,     // Allows connection to cloud-hosted DBs with self-signed SSL certificates
  },
});

// Test database connection and log result
pool.connect(err => {
  if (err) {
    console.error('❌ Error connecting to the database:', err.message);
    return;
  }
  console.log('✅ Connected to PostgreSQL Database');
});

// 🛡️ Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const { authorization } = req.headers; // Extract the Authorization header

  // If no Authorization header is found, deny access
  if (!authorization) {
    return res.status(401).json({ message: "No token provided" });
  }

  // Bearer tokens are usually sent as "Bearer <token>", so split it
  const token = authorization.split(" ")[1];

  try {
    // Verify the token using your secret key
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Store decoded userId in the request object so next middleware/routes can use it
    req.userId = decoded.userId;

    next(); // Continue to the next middleware or route handler
  } catch (err) {
    // If token is invalid or expired
    return res.status(401).json({ message: "Token invalid or expired" });
  }
};

// 🛡️ Middleware for Admin Panel
const authenticateAdmin = (req, res, next) => {
  const { authorization } = req.headers;

  if (!authorization) {
    return res.status(401).json({ message: "No admin token provided" });
  }

  const token = authorization.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if the token belongs to an admin
    if (decoded.usertype !== 'admin') {
      return res.status(403).json({ message: "Access denied. Admins only." });
    }

    req.user = decoded; // contains { idusers, username, usertype }
    next();
  } catch (err) {
    return res.status(401).json({ message: "Token invalid or expired" });
  }
};

// Example of logging an environment variable
console.log("Value before JSON.parse:", process.env.SOMETHING);

// 🔥 Firebase Admin setup

// Parse the service account credentials from your environment variable.
// The GOOGLE_SERVICE_ACCOUNT should contain the entire JSON key from Firebase,
// stored as a single-line string in your .env file.
const serviceAccount = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT);

// Log to confirm if the variable exists (for debugging)
console.log('GOOGLE_SERVICE_ACCOUNT:', process.env.GOOGLE_SERVICE_ACCOUNT ? 'Exists' : 'Not set');

// Initialize Firebase Admin with the credentials
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount), // Authenticates your server to Firebase
});

// Confirm initialization
console.log('✅ Firebase Admin initialized with project:', serviceAccount.project_id);

// 🧠 In-memory map for active tokens (idpatient → fcmToken)
// This temporarily stores active FCM tokens for logged-in users.
// Example: activeTokens.set(3, 'abcd1234...') means patient with ID 3 is using that token.
const activeTokens = new Map();

// 📩 Helper function to send a notification to a specific user
async function sendNotificationToUser(fcmToken, appt, options = {}) {
  try {
    // Convert the appointment date to a readable format in Asia/Manila timezone
    const utcDate = new Date(appt.date);
    const manilaDateStr = utcDate.toLocaleString('en-US', {
      timeZone: 'Asia/Manila',
      month: 'long',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    // 🚀 Send the notification using Firebase Admin
    await admin.messaging().send({
      token: fcmToken, // The user's device FCM token
      data: {
        appointmentTime: utcDate.toISOString(), // Optional: extra data for your app
      },
      notification: {
        title: options.customTitle || 'Upcoming appointment', // Notification title
        body: options.customBody || `Your appointment is scheduled at ${manilaDateStr}`, // Notification message
      },
      android: {
        notification: {
          channelId: 'appointment_channel_id', // Must match the channel created in your mobile app
        },
      },
    });

    console.log(`✅ Sent notification to ${fcmToken.slice(0, 10)}...`); // Log confirmation
  } catch (error) {
    console.error('❌ Error sending notification:', error); // Log any sending errors
  }
}

// Get appointments that fall within a 1-minute window of the target dates
async function getAppointmentsAtTimes(targetDates) {

  const windowDuration = 30 * 1000; // 30 seconds before and after the target time

  // Create small time windows (start and end) around each target date
  const timeWindows = targetDates.map(date => {
    const start = new Date(date.getTime() - windowDuration); // start time (30s before)
    const end = new Date(date.getTime() + windowDuration);   // end time (30s after)
    return { start, end };
  });

  // Build dynamic SQL conditions for multiple time windows
  // Example: date BETWEEN $1 AND $2 OR date BETWEEN $3 AND $4 ...
  const conditions = timeWindows
    .map((_, idx) => `date BETWEEN $${idx * 2 + 1} AND $${idx * 2 + 2}`)
    .join(' OR ');

  // Prepare parameter values for the SQL query
  const values = [];
  timeWindows.forEach(window => {
    values.push(window.start.toISOString());
    values.push(window.end.toISOString());
  });

  // SQL query to get appointments that match the time windows
  const query = `SELECT * FROM appointment WHERE (${conditions})`;

  try {
    // Run query and log the results
    const result = await pool.query(query, values);
    console.log('Appointments fetched from DB:', result.rows);

    return result.rows; // return appointments found
  } catch (err) {
    // If query fails, log the error and return an empty list
    console.error('DB query error:', err);
    return [];
  }
}

// 🕒 Cron job to check upcoming appointments and notify logged-in users
// This runs every minute to remind patients of their upcoming appointments
cron.schedule('* * * * *', async () => {
  console.log(`[CRON] Running appointment reminder check at ${new Date().toISOString()}`);

  // Get the current date and time
  const now = new Date();

  // Create reminder times: 3 days, 1 day, and 1 hour before the appointment
  const threeDaysLater = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000); // 3 days before
  const oneDayLater = new Date(now.getTime() + 24 * 60 * 60 * 1000);        // 1 day before
  const oneHourLater = new Date(now.getTime() + 60 * 60 * 1000);            // 1 hour before

  // Log which appointment times are being checked
  console.log('🗓 Checking appointment windows for:', {
    '3 days before': threeDaysLater.toISOString(),
    '1 day before': oneDayLater.toISOString(),
    '1 hour before': oneHourLater.toISOString(),
  });

  // Get all appointments that match any of the reminder times
  const appointmentsToNotify = await getAppointmentsAtTimes([
    threeDaysLater,
    oneDayLater,
    oneHourLater
  ]);

  // Log how many appointments were found
  console.log(`🔍 Found ${appointmentsToNotify.length} appointments to notify`);

  // Loop through each appointment found
  for (const appt of appointmentsToNotify) {

    // Get the patient’s Firebase Cloud Messaging (FCM) token from the database
    const { rows } = await pool.query('SELECT fcm_token FROM users WHERE idusers = $1', [appt.idpatient]);
    const token = rows[0]?.fcm_token;
   
    // If the patient has an active FCM token, send a notification
    if (token) {
      await sendNotificationToUser(token, appt);
      console.log(`📅 Notification sent for appointment on ${appt.date.toISOString()} (Patient ID: ${appt.idpatient})`);
    } else {
      // If the user is not logged in or has no token, skip notification
      console.warn(`⚠️ Skipped: User ${appt.idpatient} not logged in (no active token)`);
    }
  }
});

const { Storage } = require('@google-cloud/storage'); // Import Google Cloud Storage client
const path = require('path');                         // Node.js module for working with file paths
const multer = require('multer');                     // Middleware to handle file uploads
const fs = require('fs');                             // Node.js module to interact with the file system

// Multer setup: store uploaded files temporarily in the "temp/" folder
const upload = multer({ dest: 'temp/' });

// Write Google Cloud service account key from environment variable to a temp file
// This allows the Google Cloud client to authenticate
const keyFilePath = path.join(__dirname, 'service-account.json');
fs.writeFileSync(keyFilePath, process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);

// Google Cloud Storage client setup using the key file
const storage = new Storage({ keyFilename: keyFilePath });

// Reference a specific bucket in Google Cloud Storage
// This bucket ('toothpix-models') will store your uploaded files
const bucket = storage.bucket('toothpix-models');

// 📌 Route to upload "BEFORE" dental 3D model (GLTF + optional BIN)
app.post(
  '/api/uploadModel/before',
  authenticateAdmin, // ✅ Protect this route for admins only
  upload.fields([
    { name: 'gltf', maxCount: 1 },
    { name: 'bin', maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const idrecord = req.body.idrecord; // Record ID from frontend
      const adminId = req.user.idusers; // ✅ Admin ID from token

      // -------- Upload GLTF file --------
      const gltfFile = req.files['gltf'][0];
      const gltfFileName = `DentalModel_${idrecord}.gltf`;
      const gltfPath = `models/${gltfFileName}`;
      await bucket.upload(gltfFile.path, {
        destination: gltfPath,
        contentType: 'model/gltf+json',
      });
      fs.unlinkSync(gltfFile.path);

      // -------- Upload BIN file (optional) --------
      let binPath = null;
      if (req.files['bin']) {
        const binFile = req.files['bin'][0];
        const binFileName = `DentalModel_${idrecord}.bin`;
        binPath = `models/${binFileName}`;
        await bucket.upload(binFile.path, {
          destination: binPath,
          contentType: 'application/octet-stream',
        });
        fs.unlinkSync(binFile.path);
      }

      // -------- Store the file paths in PostgreSQL --------
      await pool.query(
        `INSERT INTO dental_models (idrecord, before_model_url, before_model_bin_url, before_uploaded_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (idrecord) DO UPDATE
         SET before_model_url = EXCLUDED.before_model_url,
             before_model_bin_url = EXCLUDED.before_model_bin_url,
             before_uploaded_at = NOW()`,
        [idrecord, gltfPath, binPath]
      );

      // -------- Log admin activity --------
      await logActivity(
        adminId,
        'UPLOAD',
        'dental_models',
        idrecord,
        `Uploaded BEFORE model for record ID ${idrecord}`
      );

      // ✅ Return success
      return res.json({ success: true, gltfPath, binPath });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ success: false, error: err.message });
    }
  }
);

// 📌 Fetch dental model for a specific record and generate temporary access URLs
app.get('/api/app/dental_models/:idrecord', async (req, res) => {
  const { idrecord } = req.params; // Get record ID from URL
  const query = 'SELECT * FROM dental_models WHERE idrecord = $1';

  try {
    const result = await pool.query(query, [idrecord]);

    // If no record exists, return 404
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No model found for this idrecord' });
    }

    const row = result.rows[0];

    // Generate signed URL for GLTF file (valid 10 minutes)
    const [gltfSignedUrl] = await bucket.file(row.before_model_url).getSignedUrl({
      action: 'read',
      expires: Date.now() + 10 * 60 * 1000, // 10 minutes
    });

    // Generate signed URL for BIN file if it exists
    let binSignedUrl = null;
    if (row.before_model_bin_url) {
      [binSignedUrl] = await bucket.file(row.before_model_bin_url).getSignedUrl({
        action: 'read',
        expires: Date.now() + 10 * 60 * 1000,
      });
    }

    // Return signed URLs to frontend
    return res.json({
      id: row.id,
      idrecord: row.idrecord,
      gltfUrl: gltfSignedUrl,
      binUrl: binSignedUrl,
    });
  } catch (err) {
    console.error('Error fetching model:', err.message);
    return res.status(500).json({ message: 'Error fetching model', error: err.message });
  }
});

// 📌 Generate payment report for all records
app.get('/api/reports/payments', async (req, res) => {
  const query = `
    SELECT 
      r.idrecord,
      CASE 
        WHEN r.idpatient IS NOT NULL THEN CONCAT(p.firstname, ' ', p.lastname)
        ELSE a.patient_name
      END AS patient_name,
      CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,
      a.date AS appointment_date,
      STRING_AGG(s.name, ', ') AS services, -- Combine all services for that appointment
      SUM(s.price) AS total_price,          -- Total price of all services
      r.total_paid,
      r.paymentstatus
    FROM records r
    LEFT JOIN users p ON p.idusers = r.idpatient       -- Patient (if exists)
    JOIN users d ON d.idusers = r.iddentist            -- Dentist
    JOIN appointment a ON a.idappointment = r.idappointment
    JOIN appointment_services aps ON aps.idappointment = a.idappointment
    JOIN service s ON s.idservice = aps.idservice
    GROUP BY 
      r.idrecord, 
      p.firstname, p.lastname, 
      a.patient_name, 
      d.firstname, d.lastname, 
      a.date, 
      r.total_paid, 
      r.paymentstatus
    ORDER BY 
      LOWER(
        CASE 
          WHEN r.idpatient IS NOT NULL THEN CONCAT(p.firstname, ' ', p.lastname)
          ELSE a.patient_name
        END
      ),
      a.date DESC;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No payment records found' });
    }

    // Return all payment records with patient, dentist, services, total price, and payment status
    return res.status(200).json({ payments: result.rows });
  } catch (err) {
    console.error('Error fetching payment report:', err.message);
    return res.status(500).json({ message: 'Error fetching payment report', error: err.message });
  }
});

// API endpoint to fetch all dental records along with appointment and service details
app.get('/api/reports/records', async (req, res) => {
  const query = `
    SELECT 
      r.idrecord,
      -- Determine patient name: use full name from users if patient exists, otherwise use appointment's patient_name
      CASE 
        WHEN a.idpatient IS NOT NULL THEN CONCAT(p.firstname, ' ', p.lastname)
        ELSE a.patient_name
      END AS patient_name,
      -- Dentist's full name
      CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,
      a.date AS appointment_date,          -- Appointment date
      STRING_AGG(s.name, ', ') AS services, -- List of services
      r.treatment_notes                     -- Notes for this record
    FROM records r
    JOIN appointment a ON a.idappointment = r.idappointment
    LEFT JOIN users p ON p.idusers = a.idpatient
    JOIN users d ON d.idusers = r.iddentist
    JOIN appointment_services aps ON aps.idappointment = a.idappointment
    JOIN service s ON s.idservice = aps.idservice
    WHERE a.status != 'cancelled'          -- Ignore cancelled appointments
    GROUP BY 
      r.idrecord, 
      p.firstname, 
      p.lastname, 
      a.patient_name, 
      d.firstname, 
      d.lastname, 
      a.date, 
      r.treatment_notes
    ORDER BY
      -- Sort by patient name (case-insensitive) and then by appointment date
      LOWER(
        CASE 
          WHEN a.idpatient IS NOT NULL THEN CONCAT(p.firstname, ' ', p.lastname)
          ELSE a.patient_name
        END
      ),
      a.date
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

    // Return all records in JSON format
    return res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching record report:', err.message);
    return res.status(500).json({ message: 'Error fetching record report', error: err.message });
  }
});

// API endpoint to fetch today's appointments with patient and service details
app.get('/api/reports/today-appointments', async (req, res) => {
  const query = `
    SELECT 
      a.idappointment,
      -- Format time in Manila timezone (HH24:MI)
      to_char(a.date AT TIME ZONE 'Asia/Manila', 'HH24:MI') AS time,
      -- Use user's full name if exists, otherwise use appointment's patient_name
      COALESCE(u.firstname || ' ' || u.lastname, a.patient_name) AS patient_name,
      -- Aggregate all services for the appointment
      STRING_AGG(s.name, ', ') AS services
    FROM appointment a
    LEFT JOIN users u ON u.idusers = a.idpatient
    LEFT JOIN appointment_services aps ON aps.idappointment = a.idappointment
    LEFT JOIN service s ON s.idservice = aps.idservice
    -- Only fetch appointments for today in Manila timezone
    WHERE DATE(a.date AT TIME ZONE 'Asia/Manila') = CURRENT_DATE
    GROUP BY a.idappointment, a.date, u.firstname, u.lastname, a.patient_name
    ORDER BY 
      to_char(a.date AT TIME ZONE 'Asia/Manila', 'HH24:MI') ASC,
      a.idappointment ASC
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found for today' });
    }

    // Return today's appointments in JSON
    return res.status(200).json({ appointments: result.rows });
  } catch (err) {
    console.error('Error fetching today\'s appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching today\'s appointments', error: err.message });
  }
});

// API endpoint to fetch 3D dental models along with patient, dentist, and appointment info
app.get('/api/website/3dmodels', async (req, res) => {
  const query = `
    SELECT
      r.idrecord,  -- Record ID
      rm.id AS model_id,  -- Dental model ID
      rm.before_model_url,  -- GLTF file path before treatment
      rm.after_model_url,   -- GLTF file path after treatment
      rm.before_uploaded_at,  -- Upload timestamp for before model
      rm.after_uploaded_at,   -- Upload timestamp for after model
      rm.created_at AS model_created_at,  -- Model record creation timestamp
      CONCAT(p.firstname, ' ', p.lastname) AS patient_name,  -- Patient full name
      CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,  -- Dentist full name
      r.treatment_notes,  -- Notes about the treatment
      a.date AS appointment_date  -- Appointment date
    FROM records r
    JOIN users p ON r.idpatient = p.idusers  -- Get patient info
    JOIN users d ON r.iddentist = d.idusers  -- Get dentist info
    JOIN appointment a ON r.idappointment = a.idappointment  -- Get appointment info
    LEFT JOIN dental_models rm ON rm.idrecord = r.idrecord  -- Optional 3D model info
    WHERE r.idpatient IS NOT NULL  -- Only include records linked to a patient
    ORDER BY a.date DESC, rm.created_at DESC NULLS LAST;  -- Latest appointments and models first
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

    return res.status(200).json({ models: result.rows });  // Return fetched models
  } catch (err) {
    console.error('Error fetching 3D models:', err.message);
    return res.status(500).json({ message: 'Error fetching 3D models', error: err.message });
  }
});

// API endpoint to fetch top services based on usage, unique patients, and revenue
app.get('/api/reports/top-services', async (req, res) => {
  const query = `
    SELECT 
      s.name AS service_name,  -- Service name
      COALESCE(COUNT(aps.idappointment), 0) AS usage_count,  -- Total times the service was used
      COALESCE(COUNT(DISTINCT a.idappointment), 0) AS unique_appointments,  -- Number of distinct appointments including this service
      COALESCE(COUNT(DISTINCT 
        CASE 
          WHEN a.idpatient IS NOT NULL THEN a.idpatient::text  -- If patient exists, use patient ID
          ELSE a.patient_name  -- Otherwise, use the name entered for walk-in/guest
        END
      ), 0) AS unique_patients,  -- Number of unique patients who received this service
      COALESCE(SUM(s.price), 0) AS total_revenue  -- Total revenue generated from this service
    FROM service s
    LEFT JOIN appointment_services aps ON s.idservice = aps.idservice  -- Join to link service usage to appointments
    LEFT JOIN appointment a ON a.idappointment = aps.idappointment AND a.status = 'completed'  -- Only consider completed appointments
    LEFT JOIN records r ON r.idappointment = a.idappointment  -- Optional: join records for additional info
    GROUP BY s.name
    ORDER BY usage_count DESC;  -- Most used services appear first
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No service usage data found' });
    }

    return res.status(200).json({ topServices: result.rows });  // Return top services report
  } catch (err) {
    console.error('Error fetching top services report:', err.message);
    return res.status(500).json({ message: 'Error fetching top services report', error: err.message });
  }
});

// GET /api/website/appointments/report - Fetch all appointments with details
app.get('/api/website/appointments/report', async (req, res) => {
  // SQL query to fetch appointment details including patient, dentist, date, status, notes, and services
  const query = `
    SELECT 
      a.idappointment,
      CONCAT(p.firstname, ' ', p.lastname) AS patient_name,  -- Patient full name
      CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,  -- Dentist full name
      TO_CHAR(a.date AT TIME ZONE 'Asia/Manila', 'YYYY-MM-DD HH12:MI AM') AS formatted_date,  -- Formatted date/time
      a.status,  -- Appointment status
      a.notes,   -- Any notes
      STRING_AGG(s.name, ', ') AS services  -- List of services in this appointment
    FROM appointment a
    LEFT JOIN users p ON a.idpatient = p.idusers
    LEFT JOIN users d ON a.iddentist = d.idusers
    LEFT JOIN appointment_services aps ON aps.idappointment = a.idappointment
    LEFT JOIN service s ON aps.idservice = s.idservice
    GROUP BY a.idappointment, patient_name, dentist_name, a.date, a.status, a.notes
    ORDER BY a.idappointment;
  `;

  try {
    // Execute the query
    const result = await pool.query(query);

    // If no appointments found, return 404
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    // Return all appointments in JSON format
    return res.status(200).json({
      records: result.rows
    });
  } catch (err) {
    // Handle database errors
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});

// GET /api/fullreport
// Fetch appointments with optional filters for status, dentist, and date
app.get('/api/fullreport', async (req, res) => {
  const { status, dentist, date } = req.query;

  // Base query to fetch appointment, patient, dentist, payment, and service details
  let query = `
    SELECT
      a.idappointment AS id,
      CONCAT(p.firstname, ' ', p.lastname) AS patient,  -- Patient full name
      CONCAT(d.firstname, ' ', d.lastname) AS dentist,  -- Dentist full name
      a.status,                                        -- Appointment status
      a.date,                                          -- Appointment date/time
      r.paymentstatus,                                 -- Payment status
      r.total_paid,                                    -- Total paid for this record
      s.name AS service,                               -- Service name
      s.price AS service_price                         -- Service price
    FROM appointment a
    JOIN users p ON a.idpatient = p.idusers           -- Link patient
    JOIN users d ON a.iddentist = d.idusers          -- Link dentist
    LEFT JOIN records r ON a.idappointment = r.idappointment  -- Optional payment record
    LEFT JOIN appointment_services aps ON a.idappointment = aps.idappointment  -- Link services
    LEFT JOIN service s ON aps.idservice = s.idservice           -- Service details
    WHERE 1=1
  `;

  const params = [];

  // ✅ Optional filter by appointment status
  if (status) {
    query += ` AND a.status ILIKE $${params.length + 1}`;
    params.push(`%${status}%`);
  }

  // ✅ Optional filter by dentist name
  if (dentist) {
    query += ` AND CONCAT(d.firstname, ' ', d.lastname) ILIKE $${params.length + 1}`;
    params.push(`%${dentist}%`);
  }

  // ✅ Optional filter by appointment date
  if (date) {
    query += ` AND DATE(a.date) = $${params.length + 1}`;
    params.push(date);
  }

  // ✅ Sort results by newest appointment first
  query += ` ORDER BY a.date DESC`;

  try {
    // Execute query with parameters
    const result = await pool.query(query, params);

    // Return all matched records
    return res.json(result.rows);
  } catch (err) {
    console.error('Error fetching report data:', err);
    return res.status(500).json({ error: 'Failed to fetch report data' });
  }
});

// API endpoint to register a new user
app.post("/api/app/register", async (req, res) => {
  const { username, email, password, usertype, firstname, lastname } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // ✅ Check required fields
  if (!username || !email || !password || !usertype || !firstname || !lastname) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // ✅ Validate email format
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  try {
    // ✅ Check if email already exists
    const existingEmail = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingEmail.rows.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // ✅ Check if username already exists
    const existingUsername = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (existingUsername.rows.length > 0) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // ✅ Hash the password for security
    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Insert new user into database
    const newUser = await pool.query(
      `INSERT INTO users (username, email, password, usertype, firstname, lastname)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [username, email, hashedPassword, usertype, firstname, lastname]
    );

    // ✅ Exclude password from response
    const { password: _, ...userWithoutPassword } = newUser.rows[0];

    // ✅ Send success response with user info (without password)
    return res.status(201).json({
      message: "User registered successfully.",
      user: userWithoutPassword,
    });
  } catch (err) {
    console.error("Error in /register:", err.message);
    return res.status(500).json({ message: "Internal server error", error: err.message });
  }
});

// POST /api/website/login - Admin login endpoint
app.post('/api/website/login', [
  // Validate input: username must be at least 3 chars, password at least 6 chars
  body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {

  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;

  try {
    // Fetch user by username from the database
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    // If user does not exist, return error
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found.' });
    }

    const user = result.rows[0];

    // Check if user is an admin
    if (user.usertype !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Admins only.' });
    }

    // Compare entered password with hashed password in database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    // ✅ Generate JWT token valid for 24 hours, now includes admin ID
    const token = jwt.sign(
      { idusers: user.idusers, username: user.username, usertype: user.usertype },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // ✅ Return success response with token and full admin info
    return res.status(200).json({
      message: 'Admin login successful',
      token,
      user: {
        idusers: user.idusers,
        username: user.username,
        usertype: user.usertype,
      },
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Error querying database' });
  }
});

// GET /api/admin - Fetch all admin users
app.get('/api/admin', async (req, res) => {
  // SQL query to get id, email, and username of users with 'admin' usertype
  const query = "SELECT idusers, email, username FROM users WHERE usertype = 'admin'";

  try {
    // Execute query
    const result = await pool.query(query);

    // If no admins found, return 404
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No admin found' });
    }

    // Return list of admins
    return res.status(200).json({
      admin: result.rows
    });
  } catch (err) {
    // Handle database errors
    console.error('Error fetching admin:', err.message);
    return res.status(500).json({ message: 'Error fetching admin', error: err.message });
  }
});

// API endpoint to create a new appointment
app.post('/api/app/appointments', async (req, res) => {
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
      // Appointment for registered patient
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, NULL AS patient_name
      `;
      insertValues = [idpatient, iddentist, date, status || 'pending', notes || ''];
    } else {
      // Appointment for walk-in patient (patient not registered)
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes, patient_name)
        VALUES (NULL, $1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      insertValues = [iddentist, date, status || 'pending', notes || '', patient_name];
    }

    // Insert appointment into database
    const appointmentResult = await pool.query(insertQuery, insertValues);
    const appointment = appointmentResult.rows[0];

    // Insert associated services for this appointment
    const serviceInsertPromises = idservice.map(serviceId => {
      const insertServiceQuery = `
        INSERT INTO appointment_services (idappointment, idservice)
        VALUES ($1, $2)
      `;
      return pool.query(insertServiceQuery, [appointment.idappointment, serviceId]);
    });
    await Promise.all(serviceInsertPromises);

    // Send notification to dentist only
    try {
      // Convert date to Manila timezone for display
      const utcDate = new Date(appointment.date);
      const formatted = utcDate.toLocaleString('en-US', {
        timeZone: 'Asia/Manila',
        month: 'long',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      // Get dentist FCM token to send notification
      const { rows } = await pool.query(`SELECT fcm_token FROM users WHERE idusers = $1`, [iddentist]);
      const dentistToken = rows[0]?.fcm_token;

      if (dentistToken) {
        await sendNotificationToUser(dentistToken, appointment, {
          customTitle: '📥 New Appointment Request',
          customBody: `A patient has requested an appointment on ${formatted}.`,
        });
      } else {
        console.warn(`⚠️ No FCM token found for dentist with id ${iddentist}`);
      }
    } catch (notifErr) {
      console.error('❌ Failed to send notification to dentist:', notifErr.message);
    }

    // Return success response with appointment details
    return res.status(201).json({
      message: 'Appointment created successfully',
      appointment,
    });

  } catch (err) {
    console.error('❌ Error creating appointment:', err.message);
    return res.status(500).json({ message: 'Error creating appointment', error: err.message });
  }
});

// API endpoint to fetch admin dashboard data
app.get('/api/website/admindashboard', async (req, res) => {
  const query = `
    WITH 
    -- Total appointments for today
    appointments_today AS (
      SELECT COUNT(*) AS total
      FROM appointment
      WHERE DATE(date AT TIME ZONE 'Asia/Manila') = CURRENT_DATE
    ),
    -- Total earnings for this month
    this_month_earnings AS (
      SELECT 
        SUM(r.total_paid) AS total_earnings
      FROM records r
      JOIN appointment a ON a.idappointment = r.idappointment
      WHERE r.paymentstatus IN ('paid', 'partial')
        AND DATE_TRUNC('month', a.date AT TIME ZONE 'Asia/Manila') = DATE_TRUNC('month', CURRENT_DATE)
    ),
    -- Top 3 most used services
    top_services AS (
      SELECT 
        s.name,
        COUNT(*) AS usage_count
      FROM appointment_services aps
      JOIN service s ON aps.idservice = s.idservice
      GROUP BY s.name
      ORDER BY usage_count DESC
      LIMIT 3
    ),
    -- Top 3 dentists based on completed appointments
    top_dentists AS (
      SELECT 
        a.iddentist,
        CONCAT(u.firstname, ' ', u.lastname) AS fullname,
        COUNT(*) AS patients_helped
      FROM appointment a
      JOIN users u ON u.idusers = a.iddentist
      WHERE a.status = 'completed'
      GROUP BY a.iddentist, fullname
      ORDER BY patients_helped DESC
      LIMIT 3
    ),
    -- Monthly sales for the past 12 months
    monthly_sales AS (
      SELECT 
        TO_CHAR(a.date AT TIME ZONE 'Asia/Manila', 'YYYY-MM') AS month,
        SUM(r.total_paid) AS total_sales
      FROM records r
      JOIN appointment a ON a.idappointment = r.idappointment
      WHERE r.paymentstatus IN ('paid', 'partial')
      GROUP BY month
      ORDER BY month DESC
      LIMIT 12
    )

    -- Combine all dashboard data into a single row
    SELECT 
      (SELECT total FROM appointments_today) AS totalAppointmentsToday,
      (SELECT total_earnings FROM this_month_earnings) AS thisMonthEarnings,
      (SELECT JSON_AGG(ts) FROM top_services ts) AS topServices,
      (SELECT JSON_AGG(td) FROM top_dentists td) AS topDentists,
      (SELECT JSON_AGG(ms) FROM monthly_sales ms) AS monthlySales;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No dashboard data found' });
    }

    const row = result.rows[0];

    // Return structured dashboard data
    return res.status(200).json({
      totalAppointmentsToday: row.totalappointmentstoday || 0,
      thisMonthEarnings: parseFloat(row.thismonthearnings) || 0,
      topServices: row.topservices || [],
      topDentists: row.topdentists || [],
      monthlySales: row.monthlysales || [],
    });
  } catch (err) {
    console.error('Error fetching admin dashboard data:', err.message);
    return res.status(500).json({ message: 'Error fetching admin dashboard', error: err.message });
  }
});

// API endpoint to create a new appointment (with activity log)
app.post('/api/website/appointments', async (req, res) => {
  const { idpatient, iddentist, date, status, notes, idservice, patient_name, adminId } = req.body;

  // Validate required fields
  if ((!idpatient && !patient_name) || !iddentist || !date || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({
      message: 'If idpatient is not provided, patient_name is required. Also, iddentist, date, and idservice array are required.'
    });
  }

  try {
    let insertQuery, insertValues;

    if (idpatient) {
      // For registered patients
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, NULL AS patient_name
      `;
      insertValues = [idpatient, iddentist, date, status || 'pending', notes || ''];
    } else {
      // For walk-in patients
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes, patient_name)
        VALUES (NULL, $1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      insertValues = [iddentist, date, status || 'pending', notes || '', patient_name];
    }

    // Insert the appointment record
    const appointmentResult = await pool.query(insertQuery, insertValues);
    const appointment = appointmentResult.rows[0];

    // Insert appointment services
    const serviceInsertPromises = idservice.map(serviceId => {
      const insertServiceQuery = `
        INSERT INTO appointment_services (idappointment, idservice)
        VALUES ($1, $2)
      `;
      return pool.query(insertServiceQuery, [appointment.idappointment, serviceId]);
    });
    await Promise.all(serviceInsertPromises);

    // 🪵 Log admin activity (if adminId provided)
    if (adminId) {
      await logActivity(
        adminId,
        'ADD',
        'appointment',
        appointment.idappointment,
        `Created a new appointment (ID: ${appointment.idappointment}) for dentist ID ${iddentist}`
      );
    }

    // 🛎 Send notifications
    const utcDate = new Date(appointment.date);

    const notify = async (id, role) => {
      const { rows } = await pool.query(`SELECT fcm_token FROM users WHERE idusers = $1`, [id]);
      const token = rows[0]?.fcm_token;
      if (token) {
        await sendNotificationToUser(token, appointment, {
          customTitle: `📅 New Appointment`,
          customBody: `You have a new appointment on ${utcDate.toLocaleString('en-US', {
            timeZone: 'Asia/Manila',
            month: 'long',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true,
          })}`,
        });
      } else {
        console.warn(`⚠️ No FCM token found for ${role} with id ${id}`);
      }
    };

    if (idpatient) await notify(idpatient, 'patient');
    await notify(iddentist, 'dentist');

    // ✅ Return response
    return res.status(201).json({
      message: 'Appointment created, notifications sent, and activity logged successfully',
      appointment,
    });

  } catch (err) {
    console.error('❌ Error creating appointment:', err.message);
    return res.status(500).json({ message: 'Error creating appointment', error: err.message });
  }
});


// API endpoint to get patient reports
app.get('/api/website/report/patients', async (req, res) => {
  try {
    const query = `
      SELECT  
        p.idusers AS patient_id,
        CONCAT(p.firstname, ' ', p.lastname) AS patient_name,
        p.birthdate,
        p.gender,
        a.date AS appointment_date,
        STRING_AGG(DISTINCT s.name, ', ') AS services,  -- All services in that appointment
        r.treatment_notes,
        CONCAT(d.firstname, ' ', d.lastname) AS doctor_name,
        SUM(s.price) AS total_amount
      FROM users p
      LEFT JOIN appointment a 
        ON a.idpatient = p.idusers
        AND a.status = 'completed'  -- only completed appointments
      LEFT JOIN users d 
        ON a.iddentist = d.idusers
      LEFT JOIN records r 
        ON r.idappointment = a.idappointment
      LEFT JOIN appointment_services aps 
        ON aps.idappointment = a.idappointment
      LEFT JOIN service s 
        ON aps.idservice = s.idservice
      WHERE p.usertype = 'patient'
        AND a.idappointment IS NOT NULL  -- exclude patients with no completed appointments
      GROUP BY 
        p.idusers, p.firstname, p.lastname, p.birthdate, p.gender,
        a.idappointment, a.date, d.firstname, d.lastname, r.treatment_notes
      ORDER BY patient_name ASC, appointment_date ASC;
    `;

    const result = await pool.query(query);

    // Return patient report data
    return res.status(200).json({
      message: 'Patient report fetched successfully',
      patients: result.rows
    });

  } catch (err) {
    console.error('Error fetching patient report:', err);
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all completed records for a specific patient
app.get('/api/app/patientrecords/:id', async (req, res) => { 
  const patientId = req.params.id;

  const query = `
    SELECT 
      r.idrecord,
      r.idappointment,
      r.iddentist,
      CONCAT(d.firstname, ' ', d.lastname) AS dentistFullname,  -- Dentist's full name
      a.date AS appointmentDate,  -- Appointment date
      r.paymentstatus,            -- 'paid' or 'unpaid'
      r.treatment_notes,          -- Treatment notes
      COALESCE(
        (
          SELECT STRING_AGG(s.name || ' ' || s.price,  ', ' )
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), ''
      ) AS servicesWithPrices,    -- List of services with prices
      COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) AS totalPrice,            -- Total price for appointment
      COALESCE(r.total_paid, 0) AS totalPaid,  -- Amount paid
      (COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) - COALESCE(r.total_paid, 0)) AS stillOwe    -- Remaining balance
    FROM records r
    LEFT JOIN users d ON r.iddentist = d.idusers
    LEFT JOIN appointment a ON r.idappointment = a.idappointment
    WHERE r.idpatient = $1
      AND a.status = 'completed'      -- Only completed appointments
    ORDER BY r.idrecord DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query, [patientId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No completed records found for this patient' });
    }

    // Return detailed records
    return res.status(200).json({
      message: 'Patient completed records fetched successfully',
      records: result.rows
    });
  } catch (err) {
    console.error('Error fetching patient records:', err.message);
    return res.status(500).json({ message: 'Error fetching patient records', error: err.message });
  }
});

cron.schedule('*/5 * * * *', async () => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN'); // Start transaction

    // 1. Get all appointments that are in the past and not yet completed or cancelled
    const res = await client.query(`
      SELECT idappointment, idpatient, iddentist
      FROM appointment
      WHERE date < NOW()
        AND status NOT IN ('cancelled', 'completed')
    `);

    const appointmentsToComplete = res.rows;

    if (appointmentsToComplete.length === 0) {
      console.log('No appointments to update.'); // Nothing to process
      await client.query('COMMIT'); // Commit empty transaction
      return;
    }

    // 2. Update these appointments to 'completed'
    const idsToUpdate = appointmentsToComplete.map(a => a.idappointment);
    await client.query(
      `UPDATE appointment SET status = 'completed' WHERE idappointment = ANY($1::int[])`,
      [idsToUpdate]
    );
    console.log(`Updated ${idsToUpdate.length} appointments to completed.`);

    // 3. Insert records for these appointments if they don't already exist
    for (const appt of appointmentsToComplete) {
      const { idappointment, idpatient, iddentist } = appt;

      // Check if a record already exists
      const existing = await client.query(
        `SELECT 1 FROM records WHERE idappointment = $1 LIMIT 1`,
        [idappointment]
      );

      if (existing.rowCount === 0) {
        await client.query(
          `INSERT INTO records (idappointment, idpatient, iddentist, paymentstatus, total_paid)
           VALUES ($1, $2, $3, 'unpaid', 0)`,
          [idappointment, idpatient, iddentist]
        );
        console.log(`Inserted record for appointment ID ${idappointment}`);
      } else {
        console.log(`Record already exists for appointment ID ${idappointment}`);
      }
    }

    await client.query('COMMIT'); // Commit all changes
    console.log('Appointment statuses and records updated successfully.');
  } catch (err) {
    await client.query('ROLLBACK'); // Undo changes if error occurs
    console.error('Scheduled update failed:', err.message);
  } finally {
    client.release(); // Release DB connection
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
      a.patient_name AS patientName,                             -- Fallback for walk-in patients
      a.date AS appointmentDate,                                 -- Appointment date
      r.paymentstatus,                                           -- Payment status
      r.treatment_notes,                                         -- Treatment notes
      COALESCE(
        (
          SELECT STRING_AGG(s.name || ' ' || s.price, ', ')    -- List of services with prices
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), ''
      ) AS servicesWithPrices,
      COALESCE(
        (
          SELECT SUM(s.price)                                   -- Total price of services
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) AS totalPrice,
      COALESCE(r.total_paid, 0) AS totalPaid,                   -- Total paid by patient
      (COALESCE(
        (
          SELECT SUM(s.price)                                   -- Calculate remaining balance
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) - COALESCE(r.total_paid, 0)) AS stillOwe
    FROM records r
    LEFT JOIN users p ON r.idpatient = p.idusers                -- Join with patients table
    LEFT JOIN appointment a ON r.idappointment = a.idappointment -- Join with appointment table
    WHERE r.iddentist = $1                                      -- Filter by dentist ID
    ORDER BY r.idrecord DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query, [dentistId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found for this dentist' });
    }

    return res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching dentist records:', err.message);
    return res.status(500).json({ message: 'Error fetching dentist records', error: err.message });
  }
});

app.post('/api/website/record', async (req, res) => {
  const { idpatient, patient_name, iddentist, date, services, treatment_notes } = req.body;

  // Validate required fields
  if (!iddentist || !date || !Array.isArray(services) || services.length === 0) {
    return res.status(400).json({ message: 'Missing or invalid dentist, date, or services.' });
  }
  if (!idpatient && !patient_name) {
    return res.status(400).json({ message: 'Either idpatient or patient_name is required.' });
  }

  try {
    await pool.query('BEGIN');

    // 1️⃣ Insert appointment with status = 'completed'
    let insertAppointmentQuery, insertParams;

    if (idpatient) {
      // For registered patients
      insertAppointmentQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, notes, patient_name, status)
        VALUES ($1, $2, $3, $4, NULL, 'completed')
        RETURNING idappointment
      `;
      insertParams = [idpatient, iddentist, date, ''];
    } else {
      // For walk-in patients
      insertAppointmentQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, notes, patient_name, status)
        VALUES (NULL, $1, $2, $3, $4, 'completed')
        RETURNING idappointment
      `;
      insertParams = [iddentist, date, '', patient_name];
    }

    const apptResult = await pool.query(insertAppointmentQuery, insertParams);
    const idappointment = apptResult.rows[0].idappointment;

    // 2️⃣ Insert appointment services
    for (const idservice of services) {
      await pool.query(
        `INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)`,
        [idappointment, idservice]
      );
    }

    // 3️⃣ Insert record (even if treatment_notes is empty)
    const apptDetails = await pool.query(
      `SELECT idpatient, iddentist FROM appointment WHERE idappointment = $1`,
      [idappointment]
    );
    const { idpatient: patientIdFromAppt, iddentist: dentistIdFromAppt } = apptDetails.rows[0];

    await pool.query(
      `INSERT INTO records (idpatient, iddentist, idappointment, treatment_notes, paymentstatus, total_paid)
       VALUES ($1, $2, $3, $4, 'unpaid', 0)`,
      [patientIdFromAppt, dentistIdFromAppt, idappointment, treatment_notes?.trim() || '']
    );

    await pool.query('COMMIT');

    return res.status(201).json({ 
      message: 'Appointment and record created successfully.', 
      idappointment 
    });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error creating appointment and record:', error.message);
    return res.status(500).json({ 
      message: 'Failed to create appointment and record.', 
      error: error.message 
    });
  }
});

app.put('/api/app/appointmentstatus/patient/:id', async (req, res) => {
  const id = req.params.id;                 // Appointment ID
  const { status, notes, date } = req.body; // Status, optional notes, optional new date

  // ✅ Allowed statuses a patient can set
  const allowedStatuses = ['cancelled', 'rescheduled'];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid or missing status' });
  }

  // 🕒 Generate current timestamp for automatic notes if notes not provided
  const now = new Date();
  const formattedDate = now.toISOString().slice(0, 16).replace("T", " ");
  let finalNotes = notes;

  if (!notes) {
    switch (status) {
      case 'cancelled':
        finalNotes = `Cancelled by patient on ${formattedDate}. Please contact dentist if needed.`;
        break;
      case 'rescheduled':
        if (date) finalNotes = `Rescheduled by patient to ${date}`;
        break;
    }
  }

  // 🔧 Build dynamic update query depending on which fields are provided
  const setValues = [];
  const queryParams = [];
  let query = 'UPDATE appointment SET ';

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

  query += setValues.join(', ');
  query += ` WHERE idappointment = $${setValues.length + 1} RETURNING *`;
  queryParams.push(id);

  try {
    // 🛠 Execute update
    const result = await pool.query(query, queryParams);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found.' });
    }

    const updatedAppt = result.rows[0];

    // 🛎 Notify dentist via FCM
    const dentistResult = await pool.query(
      'SELECT fcm_token FROM users WHERE idusers = $1',
      [updatedAppt.iddentist]
    );
    const fcmToken = dentistResult.rows[0]?.fcm_token;

    if (fcmToken) {
      const manilaDateStr = new Date(updatedAppt.date).toLocaleString('en-US', {
        timeZone: 'Asia/Manila',
        month: 'long',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      let customTitle = '';
      let customBody = '';

      switch (status) {
        case 'cancelled':
          customTitle = 'Appointment Cancelled by Patient';
          customBody = `Patient cancelled their appointment on ${manilaDateStr}. Please review.`;
          break;
        case 'rescheduled':
          customTitle = 'Appointment Rescheduled by Patient';
          customBody = `Patient rescheduled their appointment to ${manilaDateStr}. Please review the updated schedule.`;
          break;
      }

      await sendNotificationToUser(fcmToken, updatedAppt, {
        customTitle,
        customBody,
      });
    } else {
      console.warn(`⚠️ No FCM token found for dentist ${updatedAppt.iddentist}`);
    }

    return res.json({
      message: 'Appointment updated successfully',
      appointment: updatedAppt,
    });

  } catch (err) {
    console.error('❌ Error updating appointment:', err.message);
    return res.status(500).json({
      message: 'Error updating appointment',
      error: err.message,
    });
  }
});

app.put('/api/app/appointmentstatus/:id', async (req, res) => {
  const id = req.params.id;                 // Appointment ID
  const { status, notes, date } = req.body; // Status, optional notes, optional new date

  // ✅ Allowed statuses that a dentist can set
  const allowedStatuses = ['approved', 'cancelled', 'rescheduled'];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid or missing status' });
  }

  // 🕒 Generate current timestamp for automatic notes if notes not provided
  const now = new Date();
  const formattedDate = now.toISOString().slice(0, 16).replace("T", " ");
  let finalNotes = notes;

  if (!notes) {
    switch (status) {
      case 'approved':
        finalNotes = `Approved by dentist on ${formattedDate}`;
        break;
      case 'cancelled':
        finalNotes = `Cancelled by dentist on ${formattedDate}. Please reschedule.`;
        break;
      case 'rescheduled':
        if (date) finalNotes = `Rescheduled to ${date}`;
        break;
    }
  }

  // 🔧 Build dynamic update query depending on provided fields
  const setValues = [];
  const queryParams = [];
  let query = 'UPDATE appointment SET ';

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

  query += setValues.join(', ');
  query += ` WHERE idappointment = $${setValues.length + 1} RETURNING *`;
  queryParams.push(id);

  try {
    // 🛠 Execute update
    const result = await pool.query(query, queryParams);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found.' });
    }

    const updatedAppt = result.rows[0];

    // 🛎 Notify patient via FCM if token exists
    const userResult = await pool.query(
      'SELECT fcm_token FROM users WHERE idusers = $1',
      [updatedAppt.idpatient]
    );
    const fcmToken = userResult.rows[0]?.fcm_token;

    if (fcmToken) {
      const manilaDateStr = new Date(updatedAppt.date).toLocaleString('en-US', {
        timeZone: 'Asia/Manila',
        month: 'long',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });

      let customTitle = '';
      let customBody = '';

      switch (status) {
        case 'approved':
          customTitle = 'Appointment Confirmed!';
          customBody = `Your appointment on ${manilaDateStr} has been confirmed. See you soon!`;
          break;
        case 'cancelled':
          customTitle = 'Appointment Cancelled';
          customBody = `Your appointment on ${manilaDateStr} has been cancelled. Please reschedule.`;
          break;
        case 'rescheduled':
          customTitle = 'Appointment Rescheduled';
          customBody = `Your appointment has been moved to ${manilaDateStr}. Please check your new schedule.`;
          break;
      }

      await sendNotificationToUser(fcmToken, updatedAppt, {
        customTitle,
        customBody,
      });
    } else {
      console.warn(`⚠️ No FCM token found for patient ${updatedAppt.idpatient}`);
    }

    return res.json({
      message: 'Appointment updated successfully',
      appointment: updatedAppt,
    });

  } catch (err) {
    console.error('❌ Error updating appointment:', err.message);
    return res.status(500).json({
      message: 'Error updating appointment',
      error: err.message,
    });
  }
});

app.put('/api/website/record/:idappointment', async (req, res) => {
  const { idappointment } = req.params; // Appointment ID to update
  const { iddentist, date, services, treatment_notes } = req.body; // Incoming data

  if (!iddentist || !date || !Array.isArray(services)) {
    return res.status(400).json({ message: 'Missing or invalid dentist, date, or services.' });
  }

  try {
    await pool.query('BEGIN'); // Start transaction

    // 🔹 1. Update dentist and appointment date
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

    // 🔹 2. Handle appointment services
    const currentServicesResult = await pool.query(
      `SELECT idservice FROM appointment_services WHERE idappointment = $1`,
      [idappointment]
    );
    const currentServiceIds = currentServicesResult.rows.map(row => row.idservice);
    const newServiceIds = [...new Set(services)]; // Remove duplicates

    // Services to add/remove
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

    // 🔹 3. Update or insert treatment notes in records
    if (treatment_notes !== undefined) {
      const recordCheck = await pool.query(
        `SELECT idrecord FROM records WHERE idappointment = $1`,
        [idappointment]
      );

      if (recordCheck.rowCount > 0) {
        // Update existing record
        await pool.query(
          `UPDATE records SET treatment_notes = $1 WHERE idappointment = $2`,
          [treatment_notes, idappointment]
        );
      } else {
        // Insert new record if none exists
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

    await pool.query('COMMIT'); // Commit transaction
    return res.status(200).json({ message: 'Appointment updated successfully.' });
  } catch (err) {
    await pool.query('ROLLBACK'); // Rollback on error
    console.error('Error updating appointment:', err.message);
    return res.status(500).json({ message: 'Failed to update appointment', error: err.message });
  }
});

app.delete('/api/website/record/:id', async (req, res) => {
  const id = req.params.id; // Appointment ID to delete

  try {
    // 🔹 Delete the appointment from the appointment table
    // Note: If your DB has ON DELETE CASCADE, related rows in appointment_services and records will be removed automatically.
    // Otherwise, you may need to delete manually from those tables first.

    const deleteQuery = `DELETE FROM appointment WHERE idappointment = $1`;
    const result = await pool.query(deleteQuery, [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    return res.status(200).json({ message: 'Appointment deleted successfully' });
  } catch (error) {
    console.error('Error deleting appointment:', error.message);
    return res.status(500).json({ message: 'Error deleting appointment', error: error.message });
  }
});

app.delete('/api/app/appointments/:id', async (req, res) => {
  const appointmentId = parseInt(req.params.id, 10);

  // ✅ Validate appointment ID
  if (isNaN(appointmentId)) {
    return res.status(400).json({ message: 'Invalid appointment ID' });
  }

  console.log('Deleting appointment with id:', appointmentId, 'type:', typeof appointmentId);

  // 🔹 Delete appointment from database
  // Note: If your DB has ON DELETE CASCADE, related rows in appointment_services or records will be deleted automatically
  const query = 'DELETE FROM appointment WHERE idappointment = $1';

  try {
    const result = await pool.query(query, [appointmentId]);

    // ❌ No appointment found
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }

    // ✅ Successfully deleted
    return res.status(200).json({ message: 'Appointment deleted successfully' });
  } catch (err) {
    console.error('Error deleting appointment, possibly in use:', err);

    // 🛑 Catch foreign key constraints or other DB errors
    return res.status(500).json({ 
      message: 'Error deleting appointment, possibly in use', 
      error: err.message 
    });
  }
});

app.get('/api/website/record', async (req, res) => {
  const query = `
WITH appointment_info AS (
  SELECT
    a.idappointment,
    a.date,
    -- If patient exists, use full name; otherwise fallback to patient_name stored in appointment
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

    return res.status(200).json({
      message: 'Records fetched successfully',
      records: result.rows
    });
  } catch (err) {
    console.error('❌ Error fetching records:', err.message);
    return res.status(500).json({ 
      message: 'Error fetching records', 
      error: err.message 
    });
  }
});

app.get('/api/website/payment', async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // STEP 1: Insert missing records for past appointments (if any)
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

    // ✅ Return results with a message for clarity
    return res.status(200).json({
      message: 'Payment records fetched successfully',
      payments: result.rows
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error in payment API:', err.message);
    return res.status(500).json({
      message: 'Error fetching payments',
      error: err.message
    });
  } finally {
    client.release();
  }
});

app.put('/api/website/payment/:id', async (req, res) => {
  const { id } = req.params;
  const { total_paid, total_price } = req.body;

  // ✅ Validate inputs
  if (isNaN(total_paid) || total_paid < 0) {
    return res.status(400).json({ message: 'Invalid total_paid amount' });
  }

  if (isNaN(total_price) || total_price <= 0) {
    return res.status(400).json({ message: 'Invalid total_price amount' });
  }

  // ✅ Determine payment status based on total_paid vs total_price
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
    // STEP: Update the record with new payment details
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

    // ✅ Return success message with updated record
    return res.status(200).json({
      message: 'Payment updated successfully',
      updatedRecord: result.rows[0],
    });
  } catch (err) {
    console.error('Error updating payment:', err.message);
    return res.status(500).json({
      message: 'Failed to update payment',
      error: err.message
    });
  } finally {
    client.release();
  }
});

app.get('/appointment-services/:idappointment', async (req, res) => {
  const { idappointment } = req.params;

  try {
    // ✅ Fetch all services linked to the given appointment
    const result = await pool.query(
      `SELECT s.idservice, s.name, s.price
       FROM appointment_services aps
       JOIN service s ON aps.idservice = s.idservice
       WHERE aps.idappointment = $1`,
      [idappointment]
    );

    const services = result.rows; // contains idservice, name, and price

    // ✅ Return the list of services for the appointment
    return res.json({ services });
  } catch (error) {
    console.error('Error fetching services for appointment:', error.message);
    return res.status(500).json({ 
      error: 'Error fetching services for appointment' 
    });
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

  // ✅ Validate required fields
  if (!username || !email || !firstname || !lastname || !usertype) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  // ✅ Validate usertype
  const validUsertypes = ['patient', 'dentist', 'admin'];
  if (!validUsertypes.includes(usertype.toLowerCase())) {
    return res.status(400).json({ message: 'Invalid usertype. Must be patient, dentist, or admin.' });
  }

  try {
    // ✅ Check if user exists
    const userResult = await pool.query('SELECT * FROM users WHERE idusers = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    // ✅ Check if username already exists for another user
    const usernameCheck = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND idusers != $2',
      [username, userId]
    );
    if (usernameCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    // ✅ Check if email already exists for another user
    const emailCheck = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND idusers != $2',
      [email, userId]
    );
    if (emailCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    const existingUser = userResult.rows[0];
    let hashedPassword = existingUser.password;

    // ✅ Only hash new password if changed
    if (password && !(await bcrypt.compare(password, existingUser.password))) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    // ✅ Update user record in DB
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

    // ✅ Return updated user
    return res.status(200).json({
      message: 'User updated successfully',
      user: result.rows[0],
    });

  } catch (error) {
    console.error('Error updating user:', error.message);
    return res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});

app.put('/api/website/users/:id', async (req, res) => {
  const userId = req.params.id;
  const adminId = req.body.admin_id; // Ideally from JWT

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
    return res.status(400).json({ message: 'Invalid usertype' });
  }

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE idusers = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const existingUser = userResult.rows[0];

    const usernameCheck = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND idusers != $2 AND is_deleted = FALSE',
      [username, userId]
    );
    if (usernameCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    const emailCheck = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND idusers != $2 AND is_deleted = FALSE',
      [email, userId]
    );
    if (emailCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    let hashedPassword = existingUser.password;
    if (password && !(await bcrypt.compare(password, existingUser.password))) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

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
          medicalhistory = $12,
          updated_at = NOW()
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
    const updatedUser = result.rows[0];

    // Detect changes for undo
    const changes = {};
    const changedFields = [];

    ['username', 'email', 'usertype', 'firstname', 'lastname', 'birthdate', 'contact', 'address', 'gender', 'allergies', 'medicalhistory'].forEach(field => {
      if (existingUser[field]?.toString() !== updatedUser[field]?.toString()) {
        changes[field] = existingUser[field]; // old value for undo
        changedFields.push(field); // for description
      }
    });

    const description = changedFields.length > 0
      ? `Updated user ${firstname} ${lastname} (${changedFields.join(', ')})`
      : `Updated user ${firstname} ${lastname} (no visible changes)`;

    // ✅ Only save changed data in undo_data
    await logActivity(adminId, 'EDIT', 'users', userId, description, changes);

    return res.status(200).json({
      message: 'User updated successfully',
      user: updatedUser,
    });

  } catch (error) {
    console.error('Error updating user:', error.message);
    return res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});

app.post('/api/activity_logs/undo/:logId', async (req, res) => {
  const logId = req.params.logId;
  const adminId = req.body.admin_id;

  try {
    // 1️⃣ Get activity log
    const logResult = await pool.query(
      'SELECT * FROM activity_logs WHERE id = $1',
      [logId]
    );

    if (!logResult.rows.length) {
      return res.status(404).json({ message: 'Activity log not found' });
    }

    const log = logResult.rows[0];

    if (log.is_undone) {
      return res.status(400).json({ message: 'This action has already been undone' });
    }

    const undoData = typeof log.undo_data === 'string'
    ? JSON.parse(log.undo_data)
    : log.undo_data;


    if (!undoData || !undoData.data) {
      return res.status(400).json({ message: 'No undo data available' });
    }

    // 2️⃣ Undo based on action type
    if (log.action === 'EDIT') {
      const fields = Object.keys(undoData.data);
      const values = Object.values(undoData.data);
      const setClause = fields.map((f, idx) => `${f} = $${idx + 1}`).join(', ');

      const query = `
        UPDATE ${log.table_name}
        SET ${setClause}, updated_at = NOW()
        WHERE idusers = $${fields.length + 1}
      `;
      await pool.query(query, [...values, log.record_id]);

    } else if (log.action === 'DELETE') {
      const columns = Object.keys(undoData.data).join(', ');
      const placeholders = Object.keys(undoData.data).map((_, idx) => `$${idx + 1}`).join(', ');

      const query = `
        INSERT INTO ${log.table_name} (${columns})
        VALUES (${placeholders})
      `;
      await pool.query(query, Object.values(undoData.data));

    } else if (log.action === 'ADD') {
      const primaryKey = undoData.primary_key || 'idusers'; // fallback to idusers
      if (!undoData.data[primaryKey]) {
        return res.status(400).json({ message: 'Invalid undo data for ADD action' });
      }

      const query = `
        DELETE FROM ${log.table_name}
        WHERE ${primaryKey} = $1
      `;
      await pool.query(query, [undoData.data[primaryKey]]);
    }

    // 3️⃣ Mark log as undone
    await pool.query(
      `UPDATE activity_logs SET is_undone = TRUE, undone_at = NOW() WHERE id = $1`,
      [logId]
    );

    // 4️⃣ Log undo action
    await logActivity(
      adminId || null,
      'UNDO',
      log.table_name,
      log.record_id,
      `Undid activity log ID ${logId}`,
      null
    );

    return res.status(200).json({ message: 'Undo successful' });

  } catch (error) {
    console.error('Error performing undo:', error);
    return res.status(500).json({ message: 'Error performing undo', error: error.message });
  }
});


app.get('/api/app/records', async (req, res) => {
  const query = `
    SELECT 
      p.idusers AS idpatient, -- ✅ Patient ID
      r.idrecord,             -- ✅ Record ID
      CONCAT(p.firstname, ' ', p.lastname) AS patientFullname, -- ✅ Full name of patient
      CONCAT(d.firstname, ' ', d.lastname) AS dentistFullname, -- ✅ Full name of dentist
      r.treatment_notes,      -- ✅ Notes about the treatment
      r.paymentstatus,        -- ✅ Payment status (unpaid, partial, paid)
      r.idappointment,        -- ✅ Associated appointment ID
      a.date AS appointmentDate, -- ✅ Appointment date
      COALESCE(
        (
          SELECT STRING_AGG(s.name, ', ') -- ✅ List of services for this appointment
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), ''
      ) AS services,
      COALESCE(
        (
          SELECT SUM(s.price) -- ✅ Total price of services for this appointment
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
        ), 0
      ) AS totalPrice
    FROM users p
    LEFT JOIN records r ON r.idpatient = p.idusers    -- ✅ Join patient records
    LEFT JOIN users d ON r.iddentist = d.idusers      -- ✅ Join dentist info
    LEFT JOIN appointment a ON r.idappointment = a.idappointment -- ✅ Join appointment details
    WHERE p.usertype = 'patient'                      -- ✅ Only fetch patient records
    ORDER BY r.idrecord DESC NULLS LAST;             -- ✅ Latest records first
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

    // ✅ Return all records in response
    return res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching records:', err.message);
    return res.status(500).json({ message: 'Error fetching records', error: err.message });
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

  // ✅ Basic validation: ensure required fields are provided
  if (!username || !email || !password || !usertype || !firstname || !lastname) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  try {
    // ✅ Check if username or email already exists to avoid duplicates
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (userCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // ✅ Hash the password before saving for security
    const hashedPassword = await bcrypt.hash(password, 10); // 10 = salt rounds

    // ✅ Insert new user into database
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
      hashedPassword, // ✅ Store hashed password
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

    // ✅ Return newly created user
    return res.status(201).json({
      message: 'User created successfully',
      user: result.rows[0],
    });
  } catch (error) {
    // ✅ Handle duplicate entries (unique constraint violation)
    if (error.code === '23505') {
      return res.status(409).json({ message: 'Username or email already exists' });
    }
    console.error('Error adding user:', error.message);
    return res.status(500).json({ message: 'Error adding user', error: error.message });
  }
});

app.post('/api/website/users', async (req, res) => {
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
    medicalhistory,
    adminId // ✅ include adminId from frontend
  } = req.body;

  // Basic validation
  if (!username || !email || !password || !usertype || !firstname || !lastname) {
    return res.status(400).json({ message: 'Required fields missing' });
  }

  try {
    // Check if username or email already exists
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE (username = $1 OR email = $2) AND is_deleted = FALSE',
      [username, email]
    );

    if (userCheck.rows.length > 0) {
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
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
      hashedPassword,
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
    const newUser = result.rows[0];

    // Log admin activity (undo for ADD = DELETE, no undo_data needed)
await logActivity(
  adminId || null,
  'ADD',
  'users',
  newUser.idusers,
  `Added new ${usertype} user: ${firstname} ${lastname} (username: ${username})`,
  {
    primary_key: "idusers", // important for undo
    data: { idusers: newUser.idusers }
  }
);



    return res.status(201).json({
      message: 'User created successfully',
      user: newUser,
    });

  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ message: 'Username or email already exists' });
    }
    console.error('Error adding user:', error.message);
    return res.status(500).json({ message: 'Error adding user', error: error.message });
  }
});

app.get('/api/app/appointments/search', async (req, res) => { 
  const { dentist, patient, startDate, endDate } = req.query;

  // ✅ Prepare dynamic conditions for filtering
  let conditions = [];
  let values = [];

  // Filter by dentist ID if provided
  if (dentist) {
    conditions.push(`iddentist = $${values.length + 1}`);
    values.push(dentist);
  }

  // Filter by patient ID if provided
  if (patient) {
    conditions.push(`idpatient = $${values.length + 1}`);
    values.push(patient);
  }

  // Filter by date range if both start and end dates are provided
  if (startDate && endDate) {
    conditions.push(`DATE(date) BETWEEN $${values.length + 1} AND $${values.length + 2}`);
    values.push(startDate, endDate);
  }

  // Build WHERE clause dynamically
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  // ✅ Final query with optional filters, sorted by date ascending
  const query = `SELECT * FROM appointment ${whereClause} ORDER BY date ASC`;

  try {
    const result = await pool.query(query, values);

    // ✅ Return filtered appointments
    return res.status(200).json({ appointments: result.rows });
  } catch (err) {
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});

// ✅ Get all dentists (users with usertype = 'dentist')
app.get('/api/app/dentists', async (req, res) => {
  // Query to fetch users whose usertype is 'dentist'
  const query = "SELECT idUsers, firstname, lastname FROM users WHERE usertype = 'dentist'";

  try {
    const result = await pool.query(query);

    // Check if no dentists found
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No dentists found' });
    }

    // Return list of dentists
    return res.status(200).json({
      dentists: result.rows
    });
  } catch (err) {
    // Log error and return 500 response
    console.error('Error fetching dentists:', err.message);
    return res.status(500).json({ message: 'Error fetching dentists', error: err.message });
  }
});

// ✅ Request password reset endpoint
app.post('/api/request-reset-password', async (req, res) => {
  const { email } = req.body;

  // Validate email
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    // Step 1: Check if user exists and get existing reset token info
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

    // Step 3: Generate new reset token and set expiration (1 hour)
    const token = crypto.randomBytes(20).toString('hex');
    const expiration = new Date(Date.now() + 3600000); // 1 hour

    // Update user with new token and expiry
    const updateQuery = 'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3';
    await pool.query(updateQuery, [token, expiration, email]);

    // Step 4: Configure email transporter (Gmail)
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Construct reset link for frontend
    const resetLink = `https://cheonsafhaye14.github.io/ToothPix-website/#/resetpassword?token=${token}`;

    try {
      // Step 5: Send password reset email
      await transporter.sendMail({
        to: email,
        subject: 'Password Reset Request',
        text: `Click the following link to reset your password: ${resetLink}`,
      });

      return res.status(200).json({ message: `Password reset link sent to ${email}.` });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      return res.status(500).json({ message: 'Failed to send email', error: emailError.message });
    }
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ message: 'Database error occurred', error: err.message });
  }
});

// ✅ Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  // Validate input
  if (!token || !newPassword) {
    return res.status(400).json({ message: 'Token and new password are required' });
  }

  try {
    // Step 1: Check if token is valid and not expired
    const userQuery = 'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()';
    const userResult = await pool.query(userQuery, [token]);

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired reset token. Please request a new one.' });
    }

    const user = userResult.rows[0]; // Get user info including usertype

    // Step 2: Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Step 3: Update user password and clear reset token
    const updateQuery = `
      UPDATE users
      SET password = $1, reset_token = NULL, reset_token_expiry = NULL
      WHERE reset_token = $2
    `;
    await pool.query(updateQuery, [hashedPassword, token]);

    // Step 4: Return success message with usertype
    return res.status(200).json({ 
      message: 'Password has been successfully reset. You can now log in with your new password.', 
      usertype: user.usertype 
    });
  } catch (err) {
    console.error('Error resetting password:', err);
    return res.status(500).json({ message: 'Server error during password reset', error: err.message });
  }
});

// ✅ Create a new dental record for an appointment
app.post('/api/app/records', async (req, res) => {
  const { idpatient, iddentist, idappointment, treatment_notes, paymentstatus } = req.body;

  // Step 1: Validate required fields
  if (!idpatient || !iddentist || !idappointment) {
    return res.status(400).json({ message: 'idpatient, iddentist, and idappointment are required.' });
  }

  try {
    // Step 2: Check if a record already exists for this appointment
    const existing = await pool.query(
      'SELECT 1 FROM records WHERE idappointment = $1',
      [idappointment]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ message: 'A record for this appointment already exists.' });
    }

    // Step 3: Insert new record
    const query = `
      INSERT INTO records (idpatient, iddentist, idappointment, treatment_notes, paymentstatus)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING idrecord, idpatient, iddentist, idappointment, treatment_notes, paymentstatus
    `;

    const result = await pool.query(query, [idpatient, iddentist, idappointment, treatment_notes, paymentstatus]);
    const record = result.rows[0];

    // Step 4: Return success response with created record
    return res.status(201).json({
      message: 'Record created successfully',
      record,
    });
  } catch (err) {
    console.error('Error creating record:', err.message);
    return res.status(500).json({ message: 'Error creating record', error: err.message });
  }
});

// ✅ Get all users from the database
app.get('/api/app/users', async (req, res) => {
  const query = 'SELECT * FROM users';

  try {
    // Step 1: Execute query to fetch all users
    const result = await pool.query(query);

    // Step 2: Check if no users found
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    // Step 3: Format birthdate to YYYY-MM-DD for each user
    const formattedRows = result.rows.map(user => ({
      ...user,
      birthdate: user.birthdate
        ? new Date(user.birthdate).toISOString().split('T')[0]
        : null
    }));

    // Step 4: Return users with formatted birthdates
    return res.status(200).json({
      records: formattedRows
    });
  } catch (err) {
    console.error('Error fetching users:', err.message);
    return res.status(500).json({ message: 'Error fetching users', error: err.message });
  }
});

// ✅ Get all users from the database (excluding soft-deleted ones)
app.get('/api/website/users', async (req, res) => {
  const query = 'SELECT * FROM users WHERE is_deleted = FALSE';

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    const formattedRows = result.rows.map(user => ({
      ...user,
      birthdate: user.birthdate
        ? new Date(user.birthdate).toISOString().split('T')[0]
        : null
    }));

    return res.status(200).json({
      records: formattedRows
    });
  } catch (err) {
    console.error('Error fetching users:', err.message);
    return res.status(500).json({ message: 'Error fetching users', error: err.message });
  }
});

// ✅ Update a specific record by idrecord
app.put('/api/app/records/:idrecord', async (req, res) => {
  const { idrecord } = req.params;
  const { treatment_notes, paymentstatus } = req.body;

  // Step 1: Validate input
  if (!idrecord) {
    return res.status(400).json({ message: 'idrecord is required.' });
  }

  try {
    // Step 2: Update the record in the database
    const result = await pool.query(
      `UPDATE records
       SET treatment_notes = $1,
           paymentstatus = $2
       WHERE idrecord = $3
       RETURNING *`,
      [treatment_notes, paymentstatus, idrecord]
    );

    // Step 3: Check if the record exists
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Record not found.' });
    }

    // Step 4: Return the updated record
    return res.json({
      message: 'Record updated successfully',
      record: result.rows[0],
    });
  } catch (err) {
    console.error('Error updating record:', err.message);
    return res.status(500).json({ message: 'Error updating record', error: err.message });
  }
});

// ✅ Delete a specific record by idrecord
app.delete('/api/app/records/:id', async (req, res) => {
  const recordId = req.params.id; // Get record ID from URL
  const query = 'DELETE FROM records WHERE idrecord = $1'; // SQL query to delete record

  try {
    // Execute the delete query
    const result = await pool.query(query, [recordId]);

    // If no record was deleted, it means it was not found
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Record not found' });
    }

    // Successfully deleted
    return res.status(200).json({ message: 'Record deleted successfully' });
  } catch (err) {
    // Handle errors (e.g., record in use due to foreign key constraints)
    console.error('Error deleting, record in use:', err.message);
    return res.status(500).json({ message: 'Error deleting, record in use', error: err.message });
  }
});

// ✅ Update a specific appointment
app.put('/api/app/appointments/:id', async (req, res) => {
  const idappointment = req.params.id;
  const { idpatient, iddentist, date, status, notes, idservice, patient_name } = req.body;

  // Validate required fields
  if (!iddentist || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({ message: 'iddentist and idservice array are required.' });
  }

  if (!idpatient && !patient_name) {
    return res.status(400).json({ message: 'Either idpatient or patient_name is required.' });
  }

  try {
    // 1️⃣ Determine final date (use existing date if not provided)
    let finalDate = date;
    if (!date) {
      const existing = await pool.query('SELECT date FROM appointment WHERE idappointment = $1', [idappointment]);
      if (existing.rows.length === 0) {
        return res.status(404).json({ message: 'Appointment not found' });
      }
      finalDate = existing.rows[0].date;
    }

    // 2️⃣ Update appointment differently for registered vs walk-in patients
    let updateAppointmentQuery;
    let queryParams;

    if (idpatient) {
      // Registered patient: set patient_name to NULL
      updateAppointmentQuery = `
        UPDATE appointment
        SET idpatient = $1, iddentist = $2, date = $3, status = $4, notes = $5, patient_name = NULL
        WHERE idappointment = $6
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      queryParams = [idpatient, iddentist, finalDate, status || 'pending', notes || '', idappointment];
    } else {
      // Walk-in: set idpatient to NULL
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

    // 3️⃣ Replace all services for the appointment
    await pool.query('DELETE FROM appointment_services WHERE idappointment = $1', [idappointment]);

    const insertServicePromises = idservice.map(serviceId =>
      pool.query('INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)', [idappointment, serviceId])
    );
    await Promise.all(insertServicePromises);

    // 4️⃣ Respond with success
    return res.json({
      message: 'Appointment updated successfully',
      appointment: updatedAppointment,
    });

  } catch (error) {
    console.error('Error updating appointment:', error.message);
    return res.status(500).json({ message: 'Error updating appointment', error: error.message });
  }
});

// ✅ Get all patients (users with usertype = 'patient')
app.get('/api/app/patients', async (req, res) => {
  // Query only users with usertype 'patient'
  const query = "SELECT idUsers, firstname, lastname FROM users WHERE usertype = 'patient'";

  try {
    const result = await pool.query(query);

    // Return 404 if no patients found
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No patients found' });
    }

    // Return list of patients
    return res.status(200).json({
      patients: result.rows
    });
  } catch (err) {
    console.error('Error fetching patients:', err.message);
    return res.status(500).json({ message: 'Error fetching patients', error: err.message });
  }
});

app.get('/api/app/appointments', async (req, res) => {
  // Query to fetch all appointments, sorted by date (ascending) and then by idappointment
  const fetchQuery = 'SELECT * FROM appointment ORDER BY date ASC, idappointment ASC';

  const client = await pool.connect();

  try {
    await client.query('BEGIN'); // Start a transaction

    // Execute the query to fetch appointments
    const result = await client.query(fetchQuery);

    await client.query('COMMIT'); // Commit the transaction

    // Return 404 if no appointments found
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    // Send the sorted appointments back in the response
    return res.status(200).json({
      appointments: result.rows
    });
  } catch (err) {
    await client.query('ROLLBACK'); // Rollback transaction in case of error
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  } finally {
    client.release(); // Release the client back to the pool
  }
});

// In-memory refresh token store (for demo; move to DB for production)
let refreshTokensStore = [];

app.post('/api/app/login', [
  body('username').isLength({ min: 3 }),
  body('password').isLength({ min: 6 }),
  body('fcmToken').optional().isString(),  // validate fcmToken if provided
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password, fcmToken } = req.body;

  try {
    // Fetch user by username
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found.' });
    }

    const user = result.rows[0];

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    // Validate FCM token and update DB
    if (fcmToken) {
      // Remove the FCM token from other users who may have it
      await pool.query(
        'UPDATE users SET fcm_token = NULL WHERE fcm_token = $1 AND idusers != $2',
        [fcmToken, user.idusers]
      );

      // Assign the token to the current user
      await pool.query('UPDATE users SET fcm_token = $1 WHERE idusers = $2', [fcmToken, user.idusers]);

      console.log(`✅ Updated FCM token for user ${user.idusers}, removed from others if duplicated.`);
    }

    // Generate JWT access token
    const accessToken = jwt.sign(
      { userId: user.idusers, username: user.username, usertype: user.usertype },
      process.env.JWT_SECRET,
      { expiresIn: '24h' } // 1 day expiry
    );

    // Generate a refresh token (stored in-memory for demo purposes)
    const refreshToken = crypto.randomBytes(64).toString('hex');
    refreshTokensStore.push({ token: refreshToken, userId: user.idusers });

    // Respond with tokens and basic user info
    return res.status(200).json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: {
        id: user.idusers,
        username: user.username,
        email: user.email,
        usertype: user.usertype,
      },
    });
  } catch (err) {
    console.error('Error during login:', err.message);
    return res.status(500).json({ message: 'Error querying database', error: err.message });
  }
});

// Exchange refresh token for a new access token
app.post('/api/app/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  // Validate presence of refresh token
  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token required' });
  }

  // Find the refresh token in the in-memory store
  const storedToken = refreshTokensStore.find(rt => rt.token === refreshToken);

  if (!storedToken) {
    return res.status(403).json({ message: 'Invalid refresh token' });
  }

  try {
    // Generate a new JWT access token
    const newAccessToken = jwt.sign(
      { userId: storedToken.userId }, 
      process.env.JWT_SECRET,
      { expiresIn: '24h' } // valid for 24 hours
    );

    return res.status(200).json({ accessToken: newAccessToken });
  } catch (err) {
    console.error('Error generating access token:', err.message);
    return res.status(500).json({ message: 'Error generating new access token', error: err.message });
  }
});

// Logout endpoint
app.post('/api/app/logout', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }

  // Find the token in the store
  const storedToken = refreshTokensStore.find(rt => rt.token === refreshToken);

  if (storedToken) {
    const userId = storedToken.userId;

    // Clear any in-memory FCM token (if using in-memory mapping)
    activeTokens.delete(userId);
    console.log(`🧹 Removed in-memory FCM token for user ${userId} on logout`);

    try {
      // Clear FCM token in the database
      await pool.query('UPDATE users SET fcm_token = NULL WHERE idusers = $1', [userId]);
      console.log(`🧹 Cleared FCM token in DB for user ${userId}`);
    } catch (err) {
      console.error('❌ Error clearing FCM token in DB:', err.message);
    }
  }

  // Remove the refresh token from the in-memory store
  refreshTokensStore = refreshTokensStore.filter(rt => rt.token !== refreshToken);

  return res.status(200).json({ message: 'Logged out successfully' });
});

// Get profile route
app.get('/api/app/profile', authenticateToken, async (req, res) => {
  try {
    // Fetch user based on authenticated userId
    const getQuery = 'SELECT * FROM users WHERE idusers = $1';
    const result = await pool.query(getQuery, [req.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = result.rows[0];

    // Format birthdate to YYYY-MM-DD if available
    const formattedUser = {
      ...user,
      birthdate: user.birthdate
        ? new Date(user.birthdate).toISOString().split('T')[0]
        : null
    };

    // Remove sensitive fields before sending to client
    delete formattedUser.password;
    delete formattedUser.reset_token;

    return res.status(200).json({
      profile: formattedUser
    });

  } catch (err) {
    console.error("Error retrieving profile:", err.message);
    return res.status(500).json({ message: 'Error retrieving profile' });
  }
});

// Update profile route
app.post('/api/app/profile', authenticateToken, async (req, res) => {
  // Destructure user profile fields from request body
  const { firstname, lastname, birthdate, contact, address, gender, allergies, medicalhistory, email, username } = req.body;

  try {
    // SQL query to update user information in the database
    const updateQuery = `UPDATE users 
                         SET firstname = $1, lastname = $2, birthdate = $3, contact = $4, address = $5, gender = $6, allergies = $7, medicalhistory = $8, email = $9, username = $10
                         WHERE idusers = $11
                         RETURNING *`; // Return the updated user data

    // Execute the query with the provided user data and authenticated user ID
    const updatedUser = await pool.query(updateQuery, [firstname, lastname, birthdate, contact, address, gender, allergies, medicalhistory, email, username, req.userId]);

    // Send success response with updated profile
    return res.status(200).json({
      message: 'Profile updated successfully',
      profile: updatedUser.rows[0] // Return the first (and only) updated row
    });
  } catch (err) {
    // Log and handle errors
    console.error("Error updating profile:", err.message);
    return res.status(500).json({ message: 'Error updating profile' });
  }
});

// Route to add a new service
app.post('/api/app/services', async (req, res) => {
  // Extract fields from request body
  const { name, description, price, category } = req.body;

  // Validate 'name': must be a non-empty string
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }

  // Validate 'price': must be a number
  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }

  // Validate 'category': must be a non-empty string
  if (!category || typeof category !== 'string' || category.trim().length === 0) {
    return res.status(400).json({ message: 'Category is required and must be a non-empty string.' });
  }

  try {
    // SQL query to insert the new service into the database
    const insertQuery = `
      INSERT INTO service (name, description, price, category)
      VALUES ($1, $2, $3, $4)
      RETURNING idservice, name, description, price, category
    `;

    // Execute the insert query with sanitized inputs
    const result = await pool.query(insertQuery, [
      name.trim(),
      description || null,            // Set description to null if not provided
      parseFloat(price),              // Ensure price is a float
      category.trim()
    ]);

    const service = result.rows[0];   // Get the inserted service
    console.log('✅ Service added:', service);

    // Retrieve all FCM tokens from users (if any exist)
    const tokensResult = await pool.query(`SELECT fcm_token FROM users WHERE fcm_token IS NOT NULL`);
    const tokens = tokensResult.rows
      .map(row => row.fcm_token)
      .filter(token => typeof token === 'string' && token.trim().length > 0); // Filter out invalid tokens

    // If no FCM tokens found, skip sending notifications
    if (tokens.length === 0) {
      console.log('⚠️ No users with FCM tokens.');
      return res.status(201).json({
        message: 'Service added successfully',
        service,
        notificationSent: false,
        totalRecipients: 0,
        successfulNotifications: 0,
      });
    }

    // Notification payload content
    const notificationPayload = {
      notification: {
        title: '🦷 New Dental Service Available',
        body: `${service.name} has been added to our services list!`,
      },
      data: {
        serviceId: service.idservice.toString(),
        serviceName: service.name,
      },
      android: {
        notification: {
          channelId: 'appointment_channel_id',  // Custom Android notification channel
          priority: 'high',
        },
      }
    };

    const MAX_BATCH = 500;    // FCM max batch size
    let totalSuccess = 0;     // Count of successful notifications

    // Send notifications in batches of 500
    for (let i = 0; i < tokens.length; i += MAX_BATCH) {
      const batch = tokens.slice(i, i + MAX_BATCH); // Get current batch of tokens

      const multicastMessage = {
        tokens: batch,
        ...notificationPayload,
      };

      // Send the notification batch via FCM
      const response = await admin.messaging().sendEachForMulticast(multicastMessage);

      totalSuccess += response.successCount;
      console.log(`📩 Batch sent: ${response.successCount}/${batch.length} successes.`);

      // Log any failed notifications for debugging
      response.responses.forEach((resp, idx) => {
        if (!resp.success) {
          console.warn(`❌ Failed for token ${batch[idx]}:`, resp.error?.message);
        }
      });
    }

    // Respond with success and notification stats
    return res.status(201).json({
      message: 'Service added and notifications sent successfully',
      service,
      notificationSent: true,
      totalRecipients: tokens.length,
      successfulNotifications: totalSuccess
    });

  } catch (err) {
    // Handle and log unexpected errors
    console.error('❌ Error adding service or sending notifications:', err.stack);
    return res.status(500).json({
      message: 'Failed to add service or notify users',
      error: err.message
    });
  }
});

// Get all services route
app.get('/api/app/services', async (req, res) => {
  // SQL query to select all services from the 'service' table
  const query = 'SELECT * FROM service';

  try {
    // Execute the query
    const result = await pool.query(query);
    
    // Check if no services were found
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No services found' });
    }

    // Return the list of services
    return res.status(200).json({
      services: result.rows
    });
  } catch (err) {
    // Handle and log any errors
    console.error('Error fetching services:', err.message);
    return res.status(500).json({ message: 'Error fetching services', error: err.message });
  }
});

// Update service route
app.put('/api/app/services/:id', async (req, res) => {
  const { id } = req.params;  // Service ID from URL parameter
  const { name, description, price } = req.body;  // Data from the request body

  // Validate 'name': must be a non-empty string
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }

  // Validate 'price': must be a valid number
  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }

  // SQL query to update the service based on the provided ID
  const query = `
    UPDATE service 
    SET name = $1, description = $2, price = $3
    WHERE idservice = $4
    RETURNING idservice, name, description, price
  `;

  try {
    // Execute the update query
    const result = await pool.query(query, [name.trim(), description, parseFloat(price), id]);

    // If no service was found with the given ID
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    const updatedService = result.rows[0];  // Get the updated service

    // Respond with success and updated service data
    return res.status(200).json({
      message: 'Service updated successfully',
      service: updatedService,
    });
  } catch (err) {
    // Handle any unexpected errors
    console.error('Error updating service:', err.message);
    return res.status(500).json({ message: 'Error updating service', error: err.message });
  }
});

// Delete Service
// This endpoint deletes a specific service from the database using its ID.
// If the service doesn't exist, it returns a 404 error.
// If the service is linked to other records (in use), it returns an error message.
app.delete('/api/app/services/:id', async (req, res) => {
  const serviceId = req.params.id; // Get service ID from URL parameters
  const query = 'DELETE FROM service WHERE idservice = $1'; // SQL query to delete the service

  try {
    const result = await pool.query(query, [serviceId]); // Execute query

    if (result.rowCount === 0) {
      // If no rows were affected, service not found
      return res.status(404).json({ message: 'Service not found' });
    }

    // If deletion successful
    return res.status(200).json({ message: 'Service deleted successfully' });
  } catch (err) {
    // Catch errors (e.g., foreign key constraint)
    console.error('Error deleting, service in use:', err.message);
    return res.status(500).json({ message: 'Error deleting, service in use', error: err.message });
  }
});

// Delete User
// This endpoint removes a user from the database based on their ID.
// If the user does not exist, it responds with a 404 error message.
// If the user cannot be deleted (e.g., linked to other data), it returns a 500 error.
// 🗑️ Soft-delete a user and log the activity
app.delete('/api/website/users/:id', async (req, res) => {
  const userId = req.params.id; 
  const adminId = req.userId; // From auth middleware

  try {
    // Get existing user data before deleting
    const existingUserResult = await pool.query(
      `SELECT * FROM users WHERE idusers = $1 AND is_deleted = FALSE`,
      [userId]
    );

    if (existingUserResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found or already deleted' });
    }

    const existingUser = existingUserResult.rows[0];

    // Soft delete the user
    const result = await pool.query(
      `UPDATE users
       SET is_deleted = TRUE,
           deleted_at = NOW()
       WHERE idusers = $1
       RETURNING *`,
      [userId]
    );

    // Log activity with undo data (only store data needed to restore)
    await logActivity(
      adminId,
      'DELETE',
      'users',
      userId,
      `Soft-deleted user ${existingUser.username} (ID: ${userId})`,
      {
        data: existingUser
      }
    );

    return res.status(200).json({
      message: 'User soft-deleted successfully',
      user: result.rows[0]
    });

  } catch (err) {
    console.error('Error deleting user:', err.message);
    return res.status(500).json({ message: 'Error deleting user', error: err.message });
  }
});

const listEndpoints = require('express-list-endpoints'); // Lists all routes in your app
const morgan = require('morgan'); // Logs every HTTP request

// (Optional note: you can remove these two lines if you’re not using file logging anymore)
// const accessLog = path.join(__dirname, 'access.log'); // Log file location
// const accessLogStream = fs.createWriteStream(accessLog, { flags: 'a' }); // 'a' means append mode

// Logs every request (method + route + status) to the console
// ✅ This works best for Render since logs show up in Render’s "Logs" tab
app.use(morgan('tiny'));

// Displays all defined routes when the app starts
const endpoints = listEndpoints(app);
console.log('All registered routes:');
endpoints.forEach(e => {
  console.log(`${e.methods.join(', ')} ${e.path}`); // Example output: GET /api/app/users
});

async function logActivity(adminId, action, tableName, recordId, description, undoData = null) {
  try {
    await pool.query(
      `INSERT INTO activity_logs 
       (admin_id, action, table_name, record_id, description, undo_data)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        adminId,
        action,
        tableName,
        recordId,
        description,
        undoData ? JSON.stringify(undoData) : null
      ]
    );
  } catch (err) {
    console.error("Error logging activity:", err.message);
  }
}

// Run every day at midnight
cron.schedule('0 0 * * *', async () => {
  console.log("Running soft-delete cleanup...");

  const queries = [
    `DELETE FROM users WHERE is_deleted = TRUE AND deleted_at < NOW() - INTERVAL '30 days'`,
    `DELETE FROM service WHERE is_deleted = TRUE AND deleted_at < NOW() - INTERVAL '30 days'`,
    `DELETE FROM appointment WHERE is_deleted = TRUE AND deleted_at < NOW() - INTERVAL '30 days'`,
    `DELETE FROM records WHERE is_deleted = TRUE AND deleted_at < NOW() - INTERVAL '30 days'`
  ];

  for (const q of queries) {
    try {
      await pool.query(q);
    } catch (err) {
      console.error("Cleanup error:", err.message);
    }
  }
});

app.get('/api/website/activity_logs', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT al.*, u.username AS admin_username
       FROM activity_logs al
       LEFT JOIN users u ON al.admin_id = u.idusers
       ORDER BY al.created_at DESC`
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No activity logs found' });
    }

    return res.status(200).json({
      records: result.rows
    });
  } catch (err) {
    console.error('Error fetching activity logs:', err.message);
    return res.status(500).json({ message: 'Error fetching activity logs', error: err.message });
  }
});

app.delete('/api/website/activity_logs/:id', async (req, res) => {
  const logId = req.params.id;

  try {
    const logResult = await pool.query(
      'SELECT * FROM activity_logs WHERE id = $1',
      [logId]
    );

    if (logResult.rows.length === 0) {
      return res.status(404).json({ message: 'Activity log not found' });
    }

    await pool.query('DELETE FROM activity_logs WHERE id = $1', [logId]);

    return res.status(200).json({ message: 'Activity log deleted successfully' });
  } catch (error) {
    console.error('Error deleting activity log:', error.message);
    return res.status(500).json({ message: 'Error deleting activity log', error: error.message });
  }
});


// Start Server
// This starts the Express application and makes it listen on the specified PORT.
// When the server is running, it logs a message showing the active port.
app.listen(PORT, () => {
  console.log(`App Server running on port ${PORT}`);
});













