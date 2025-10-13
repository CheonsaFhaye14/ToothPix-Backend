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

// 📌 Generate payment report for all records (excluding deleted users, services, and appointments)
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
    LEFT JOIN users p ON p.idusers = r.idpatient AND p.is_deleted = FALSE   -- Patient (if exists)
    JOIN users d ON d.idusers = r.iddentist AND d.is_deleted = FALSE         -- Dentist
    JOIN appointment a ON a.idappointment = r.idappointment AND a.is_deleted = FALSE
    JOIN appointment_services aps ON aps.idappointment = a.idappointment
    JOIN service s ON s.idservice = aps.idservice AND s.is_deleted = FALSE
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

    return res.status(200).json({ payments: result.rows });
  } catch (err) {
    console.error('Error fetching payment report:', err.message);
    return res.status(500).json({ message: 'Error fetching payment report', error: err.message });
  }
});


// API endpoint to fetch all dental records along with appointment and service details (excluding deleted entries)
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
    JOIN appointment a ON a.idappointment = r.idappointment AND a.is_deleted = FALSE
    LEFT JOIN users p ON p.idusers = a.idpatient AND p.is_deleted = FALSE
    JOIN users d ON d.idusers = r.iddentist AND d.is_deleted = FALSE
    JOIN appointment_services aps ON aps.idappointment = a.idappointment
    JOIN service s ON s.idservice = aps.idservice AND s.is_deleted = FALSE
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
      -- Use user's full name if exists and not deleted, otherwise use appointment's patient_name
      COALESCE(u.firstname || ' ' || u.lastname, a.patient_name) AS patient_name,
      -- Aggregate all non-deleted services for the appointment
      STRING_AGG(s.name, ', ') AS services
    FROM appointment a
    LEFT JOIN users u ON u.idusers = a.idpatient AND u.is_deleted = FALSE
    LEFT JOIN appointment_services aps ON aps.idappointment = a.idappointment
    LEFT JOIN service s ON s.idservice = aps.idservice AND s.is_deleted = FALSE
    -- Only fetch appointments for today in Manila timezone and not deleted
    WHERE DATE(a.date AT TIME ZONE 'Asia/Manila') = CURRENT_DATE
      AND a.is_deleted = FALSE
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
      r.idrecord,  
      rm.id AS model_id,  
      rm.before_model_url,  
      rm.after_model_url,   
      rm.before_uploaded_at,  
      rm.after_uploaded_at,   
      rm.created_at AS model_created_at,  
      CONCAT(p.firstname, ' ', p.lastname) AS patient_name,  
      CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,  
      r.treatment_notes,  
      a.date AS appointment_date  
    FROM records r
    JOIN users p ON r.idpatient = p.idusers AND p.is_deleted = FALSE  -- Only active patients
    JOIN users d ON r.iddentist = d.idusers AND d.is_deleted = FALSE  -- Only active dentists
    JOIN appointment a ON r.idappointment = a.idappointment AND a.is_deleted = FALSE  -- Only active appointments
    LEFT JOIN dental_models rm ON rm.idrecord = r.idrecord  
    WHERE r.idpatient IS NOT NULL AND r.is_deleted = FALSE  -- Only include active records linked to a patient
    ORDER BY a.date DESC, rm.created_at DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

    return res.status(200).json({ models: result.rows });
  } catch (err) {
    console.error('Error fetching 3D models:', err.message);
    return res.status(500).json({ message: 'Error fetching 3D models', error: err.message });
  }
});


// API endpoint to fetch top services based on usage, unique patients, and revenue
app.get('/api/reports/top-services', async (req, res) => {
  const query = `
    SELECT 
      s.name AS service_name,  
      COALESCE(COUNT(aps.idappointment), 0) AS usage_count,  
      COALESCE(COUNT(DISTINCT a.idappointment), 0) AS unique_appointments,  
      COALESCE(COUNT(DISTINCT 
        CASE 
          WHEN a.idpatient IS NOT NULL THEN a.idpatient::text  
          ELSE a.patient_name  
        END
      ), 0) AS unique_patients,  
      COALESCE(SUM(s.price), 0) AS total_revenue  
    FROM service s
    LEFT JOIN appointment_services aps ON s.idservice = aps.idservice  
    LEFT JOIN appointment a 
      ON a.idappointment = aps.idappointment 
      AND a.status = 'completed' 
      AND a.is_deleted = FALSE  -- Only active appointments
    LEFT JOIN users u ON u.idusers = a.idpatient AND u.is_deleted = FALSE  -- Only active patients
    WHERE s.is_deleted = FALSE  -- Only active services
    GROUP BY s.name
    ORDER BY usage_count DESC;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No service usage data found' });
    }

    return res.status(200).json({ topServices: result.rows });  
  } catch (err) {
    console.error('Error fetching top services report:', err.message);
    return res.status(500).json({ message: 'Error fetching top services report', error: err.message });
  }
});


// GET /api/website/appointments/report - Fetch all active appointments with details
app.get('/api/website/appointments/report', async (req, res) => {
  const query = `
    SELECT 
      a.idappointment,
      CONCAT(p.firstname, ' ', p.lastname) AS patient_name,  
      CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,  
      TO_CHAR(a.date AT TIME ZONE 'Asia/Manila', 'YYYY-MM-DD HH12:MI AM') AS formatted_date,  
      a.status,  
      a.notes,  
      STRING_AGG(s.name, ', ') AS services  
    FROM appointment a
    LEFT JOIN users p ON a.idpatient = p.idusers AND p.is_deleted = FALSE  -- Only active patients
    LEFT JOIN users d ON a.iddentist = d.idusers AND d.is_deleted = FALSE  -- Only active dentists
    LEFT JOIN appointment_services aps ON aps.idappointment = a.idappointment
    LEFT JOIN service s ON aps.idservice = s.idservice AND s.is_deleted = FALSE  -- Only active services
    WHERE a.is_deleted = FALSE  -- Only active appointments
    GROUP BY a.idappointment, patient_name, dentist_name, a.date, a.status, a.notes
    ORDER BY a.idappointment;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    return res.status(200).json({ records: result.rows });
  } catch (err) {
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});

// GET /api/fullreport
// Fetch appointments with optional filters for status, dentist, and date
app.get('/api/fullreport', async (req, res) => {
  const { status, dentist, date } = req.query;

  let query = `
    SELECT
      a.idappointment AS id,
      CONCAT(p.firstname, ' ', p.lastname) AS patient,
      CONCAT(d.firstname, ' ', d.lastname) AS dentist,
      a.status,
      a.date,
      r.paymentstatus,
      r.total_paid,
      s.name AS service,
      s.price AS service_price
    FROM appointment a
    JOIN users p ON a.idpatient = p.idusers AND p.is_deleted = FALSE
    JOIN users d ON a.iddentist = d.idusers AND d.is_deleted = FALSE
    LEFT JOIN records r ON a.idappointment = r.idappointment
    LEFT JOIN appointment_services aps ON a.idappointment = aps.idappointment
    LEFT JOIN service s ON aps.idservice = s.idservice AND s.is_deleted = FALSE
    WHERE a.is_deleted = FALSE
  `;

  const params = [];

  if (status) {
    query += ` AND a.status ILIKE $${params.length + 1}`;
    params.push(`%${status}%`);
  }

  if (dentist) {
    query += ` AND CONCAT(d.firstname, ' ', d.lastname) ILIKE $${params.length + 1}`;
    params.push(`%${dentist}%`);
  }

  if (date) {
    query += ` AND DATE(a.date) = $${params.length + 1}`;
    params.push(date);
  }

  query += ` ORDER BY a.date DESC`;

  try {
    const result = await pool.query(query, params);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }
    return res.status(200).json(result.rows);
  } catch (err) {
    console.error('Error fetching report data:', err.message);
    return res.status(500).json({ error: 'Failed to fetch report data', details: err.message });
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
  const query = `
    SELECT idusers, email, username
    FROM users
    WHERE usertype = 'admin' AND is_deleted = FALSE
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No admin found' });
    }

    return res.status(200).json({ admin: result.rows });
  } catch (err) {
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
    -- Total appointments for today (exclude deleted)
    appointments_today AS (
      SELECT COUNT(*) AS total
      FROM appointment
      WHERE DATE(date AT TIME ZONE 'Asia/Manila') = CURRENT_DATE
        AND is_deleted = FALSE
    ),
    -- Total earnings for this month (exclude deleted appointments)
    this_month_earnings AS (
      SELECT SUM(r.total_paid) AS total_earnings
      FROM records r
      JOIN appointment a ON a.idappointment = r.idappointment
      WHERE r.paymentstatus IN ('paid', 'partial')
        AND DATE_TRUNC('month', a.date AT TIME ZONE 'Asia/Manila') = DATE_TRUNC('month', CURRENT_DATE)
        AND a.is_deleted = FALSE
    ),
    -- Top 3 most used services (exclude deleted services and appointments)
    top_services AS (
      SELECT s.name, COUNT(*) AS usage_count
      FROM appointment_services aps
      JOIN service s ON aps.idservice = s.idservice AND s.is_deleted = FALSE
      JOIN appointment a ON a.idappointment = aps.idappointment AND a.is_deleted = FALSE
      GROUP BY s.name
      ORDER BY usage_count DESC
      LIMIT 3
    ),
    -- Top 3 dentists based on completed appointments (exclude deleted users and appointments)
    top_dentists AS (
      SELECT a.iddentist,
             CONCAT(u.firstname, ' ', u.lastname) AS fullname,
             COUNT(*) AS patients_helped
      FROM appointment a
      JOIN users u ON u.idusers = a.iddentist AND u.is_deleted = FALSE
      WHERE a.status = 'completed' AND a.is_deleted = FALSE
      GROUP BY a.iddentist, fullname
      ORDER BY patients_helped DESC
      LIMIT 3
    ),
    -- Monthly sales for the past 12 months (exclude deleted appointments)
    monthly_sales AS (
      SELECT TO_CHAR(a.date AT TIME ZONE 'Asia/Manila', 'YYYY-MM') AS month,
             SUM(r.total_paid) AS total_sales
      FROM records r
      JOIN appointment a ON a.idappointment = r.idappointment AND a.is_deleted = FALSE
      WHERE r.paymentstatus IN ('paid', 'partial')
      GROUP BY month
      ORDER BY month DESC
      LIMIT 12
    )
    -- Combine all dashboard data into a single row
    SELECT 
      (SELECT total FROM appointments_today) AS totalAppointmentsToday,
      (SELECT total_earnings FROM this_month_earnings) AS thisMonthEarnings,
      (SELECT COALESCE(JSON_AGG(ts), '[]') FROM top_services ts) AS topServices,
      (SELECT COALESCE(JSON_AGG(td), '[]') FROM top_dentists td) AS topDentists,
      (SELECT COALESCE(JSON_AGG(ms), '[]') FROM monthly_sales ms) AS monthlySales;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No dashboard data found' });
    }

    const row = result.rows[0];

    return res.status(200).json({
      totalAppointmentsToday: parseInt(row.totalappointmentstoday) || 0,
      thisMonthEarnings: parseFloat(row.thismonthearnings) || 0,
      topServices: row.topservices,
      topDentists: row.topdentists,
      monthlySales: row.monthlysales,
    });
  } catch (err) {
    console.error('Error fetching admin dashboard data:', err.message);
    return res.status(500).json({ message: 'Error fetching admin dashboard', error: err.message });
  }
});

// API endpoint to create a new appointment (with a single activity log)
app.post('/api/website/appointments', async (req, res) => {
  const { idpatient, iddentist, date, status, notes, idservice, patient_name, adminId } = req.body;

  // Validate required fields
  if ((!idpatient && !patient_name) || !iddentist || !date || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({
      message: 'If idpatient is not provided, patient_name is required. Also, iddentist, date, and idservice array are required.'
    });
  }

  try {
    // 1️⃣ Insert the appointment
    let insertQuery, insertValues;
    if (idpatient) {
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, NULL AS patient_name
      `;
      insertValues = [idpatient, iddentist, date, status || 'pending', notes || ''];
    } else {
      insertQuery = `
        INSERT INTO appointment (idpatient, iddentist, date, status, notes, patient_name)
        VALUES (NULL, $1, $2, $3, $4, $5)
        RETURNING idappointment, idpatient, iddentist, date, status, notes, patient_name
      `;
      insertValues = [iddentist, date, status || 'pending', notes || '', patient_name];
    }

    const appointmentResult = await pool.query(insertQuery, insertValues);
    const appointment = appointmentResult.rows[0];

    // 2️⃣ Insert appointment services
    const serviceInsertPromises = idservice.map(serviceId =>
      pool.query(`INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2) RETURNING idappointment, idservice`, 
      [appointment.idappointment, serviceId])
    );

    const insertedServices = await Promise.all(serviceInsertPromises);
    const serviceIds = insertedServices.map(s => s.rows[0].idservice);

    // 3️⃣ Log a single activity with all undo data
    if (adminId) {
     await logActivity(
  adminId,
  'ADD',
  'appointment',
  appointment.idappointment,
  `Created a new appointment (ID: ${appointment.idappointment}) for dentist ID ${iddentist} with ${serviceIds.length} services`,
  { 
    primary_key: 'idappointment',
    table: 'appointment',
    data: {
      appointment: {
        idappointment: appointment.idappointment,
        iddentist: appointment.iddentist,
        status: appointment.status,
        appointment_date: appointment.date,
        notes: appointment.notes,
        idpatient: appointment.idpatient,
        patient_name: appointment.patient_name
      },
      appointment_services: insertedServices.map(s => ({
        idappointment: appointment.idappointment,
        idservice: s.rows[0].idservice
      }))
    }
  }
);
    }

    // 4️⃣ Send notifications
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
      servicesAdded: serviceIds
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
        AND a.is_deleted = FALSE
      LEFT JOIN users d 
        ON a.iddentist = d.idusers
        AND d.is_deleted = FALSE
      LEFT JOIN records r 
        ON r.idappointment = a.idappointment
      LEFT JOIN appointment_services aps 
        ON aps.idappointment = a.idappointment
      LEFT JOIN service s 
        ON aps.idservice = s.idservice
        AND s.is_deleted = FALSE
      WHERE p.usertype = 'patient'
        AND p.is_deleted = FALSE
        AND a.idappointment IS NOT NULL  -- exclude patients with no completed appointments
      GROUP BY 
        p.idusers, p.firstname, p.lastname, p.birthdate, p.gender,
        a.idappointment, a.date, d.firstname, d.lastname, r.treatment_notes
      ORDER BY patient_name ASC, appointment_date ASC;
    `;

    const result = await pool.query(query);

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
            AND s.is_deleted = FALSE
        ), ''
      ) AS servicesWithPrices,    -- List of services with prices
      COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
            AND s.is_deleted = FALSE
        ), 0
      ) AS totalPrice,            -- Total price for appointment
      COALESCE(r.total_paid, 0) AS totalPaid,  -- Amount paid
      (COALESCE(
        (
          SELECT SUM(s.price)
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
            AND s.is_deleted = FALSE
        ), 0
      ) - COALESCE(r.total_paid, 0)) AS stillOwe    -- Remaining balance
    FROM records r
    LEFT JOIN users d ON r.iddentist = d.idusers AND d.is_deleted = FALSE
    LEFT JOIN appointment a ON r.idappointment = a.idappointment AND a.is_deleted = FALSE
    WHERE r.idpatient = $1
      AND a.status = 'completed'      -- Only completed appointments
      AND r.is_deleted = FALSE
    ORDER BY r.idrecord DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query, [patientId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No completed records found for this patient' });
    }

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
      COALESCE(services.servicesWithPrices, '') AS servicesWithPrices,
      COALESCE(services.totalPrice, 0) AS totalPrice,
      COALESCE(r.total_paid, 0) AS totalPaid,
      (COALESCE(services.totalPrice, 0) - COALESCE(r.total_paid, 0)) AS stillOwe
    FROM records r
    LEFT JOIN users p ON r.idpatient = p.idusers AND p.is_deleted = FALSE
    LEFT JOIN appointment a ON r.idappointment = a.idappointment AND a.is_deleted = FALSE
    LEFT JOIN (
      SELECT 
        aps.idappointment,
        STRING_AGG(s.name || ' ' || s.price, ', ') AS servicesWithPrices,
        SUM(s.price) AS totalPrice
      FROM appointment_services aps
      JOIN service s ON aps.idservice = s.idservice AND s.is_deleted = FALSE
      JOIN appointment a ON aps.idappointment = a.idappointment AND a.is_deleted = FALSE
      GROUP BY aps.idappointment
    ) services ON services.idappointment = r.idappointment
    WHERE r.iddentist = $1
      AND r.is_deleted = FALSE
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

// ✅ Soft-delete a specific appointment (undo-ready, uniform structure, verbose logs)
app.delete('/api/website/appointments/:id', async (req, res) => {
  const appointmentId = parseInt(req.params.id, 10);
  const adminId = req.body.adminId; // optional, for logging

  console.log(`📥 Incoming request to soft-delete appointment ID: ${appointmentId}, adminId: ${adminId}`);

  // 0️⃣ Validate appointment ID
  if (isNaN(appointmentId)) {
    console.log("⚠️ Invalid appointment ID");
    return res.status(400).json({ message: 'Invalid appointment ID' });
  }

  try {
    // 1️⃣ Fetch existing appointment
    console.log("🔍 Fetching existing appointment...");
    const appointmentResult = await pool.query(
      'SELECT * FROM appointment WHERE idappointment = $1 AND is_deleted = FALSE',
      [appointmentId]
    );
    console.log("📌 Appointment query result:", appointmentResult.rows);

    if (appointmentResult.rows.length === 0) {
      console.log("⚠️ Appointment not found or already deleted");
      return res.status(404).json({ message: 'Appointment not found or already deleted' });
    }

    const existingAppointment = appointmentResult.rows[0]; // single object
    console.log("📝 Existing appointment:", existingAppointment);

    // 2️⃣ Fetch existing services
    console.log("🔍 Fetching existing appointment services...");
    const servicesResult = await pool.query(
      'SELECT * FROM appointment_services WHERE idappointment = $1',
      [appointmentId]
    );
    const appointmentServices = servicesResult.rows;
    console.log("📝 Existing services:", appointmentServices);

    // 3️⃣ Soft delete the appointment
    console.log("✏️ Soft-deleting appointment...");
    const deleteResult = await pool.query(
      'UPDATE appointment SET is_deleted = TRUE, deleted_at = NOW(), updated_at = NOW() WHERE idappointment = $1 RETURNING *',
      [appointmentId]
    );
    console.log("✅ Soft-delete query result:", deleteResult.rows[0]);

    // 4️⃣ Prepare undo-ready data
    const undoData = { 
      primary_key: 'idappointment',
      table: 'appointment',
      data: {
        appointment: existingAppointment, // single object
        appointment_services: appointmentServices
      }
    };
    console.log("🧰 Undo-ready data prepared:", undoData);

    // 5️⃣ Log admin activity (undo-ready)
    if (adminId) {
      console.log("📝 Logging activity...");
      try {
        await logActivity(
          adminId,
          'DELETE',
          'appointment',
          appointmentId,
          `Soft-deleted appointment ID ${appointmentId} with ${appointmentServices.length} linked services`,
          undoData
        );
        console.log("🪵 Activity logged successfully for appointment soft-delete.");
      } catch (logErr) {
        console.error("❌ Error logging activity:", logErr);
      }
    } else {
      console.warn("⚠️ No adminId provided; skipping activity log");
    }

    return res.status(200).json({ message: 'Appointment soft-deleted successfully' });

  } catch (err) {
    console.error('💥 Unexpected error deleting appointment:', err);
    return res.status(500).json({ message: 'Error deleting appointment', error: err.message });
  }
});

app.get('/api/website/record', async (req, res) => {
  const query = `
WITH appointment_info AS (
  SELECT
    a.idappointment,
    a.date,
    -- Use patient full name if exists and not deleted; otherwise fallback to appointment's patient_name
    CASE 
      WHEN p.idusers IS NOT NULL AND p.is_deleted = FALSE THEN CONCAT(p.firstname, ' ', p.lastname)
      ELSE a.patient_name
    END AS patient_name,
    CONCAT(d.firstname, ' ', d.lastname) AS dentist_name
  FROM appointment a
  LEFT JOIN users p ON a.idpatient = p.idusers
  JOIN users d ON a.iddentist = d.idusers
  WHERE a.is_deleted = FALSE
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
JOIN service s ON aps.idservice = s.idservice AND s.is_deleted = FALSE
LEFT JOIN records r ON r.idappointment = ai.idappointment AND r.is_deleted = FALSE
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

    // STEP 1: Insert missing records for past appointments (if any), only for non-deleted appointments
    const insertMissingRecordsQuery = `
      INSERT INTO records (idpatient, iddentist, idappointment)
      SELECT a.idpatient, a.iddentist, a.idappointment
      FROM appointment a
      LEFT JOIN records r ON r.idappointment = a.idappointment
      WHERE a.date < NOW() AT TIME ZONE 'Asia/Manila'
        AND a.is_deleted = FALSE
        AND r.idappointment IS NULL;
    `;
    await client.query(insertMissingRecordsQuery);

    // STEP 2: Fetch payment-related appointment data
    const paymentQuery = `
      SELECT
        a.idappointment,
        a.date,
        CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,
        CASE
          WHEN p.idusers IS NOT NULL AND p.is_deleted = FALSE THEN CONCAT(p.firstname, ' ', p.lastname)
          ELSE a.patient_name
        END AS patient_name,
        STRING_AGG(s.name || ' ' || s.price, ', ') AS services_with_prices,
        SUM(s.price) AS total_price,
        r.paymentstatus,
        COALESCE(r.total_paid, 0) AS total_paid,
        (SUM(s.price) - COALESCE(r.total_paid, 0)) AS still_owe
      FROM appointment a
      LEFT JOIN users p ON a.idpatient = p.idusers
      JOIN users d ON a.iddentist = d.idusers
      JOIN appointment_services aps ON a.idappointment = aps.idappointment
      JOIN service s ON aps.idservice = s.idservice AND s.is_deleted = FALSE
      JOIN records r ON r.idappointment = a.idappointment AND r.is_deleted = FALSE
      WHERE a.date < NOW() AT TIME ZONE 'Asia/Manila'
        AND a.is_deleted = FALSE
      GROUP BY 
        a.idappointment, 
        a.date, 
        CONCAT(d.firstname, ' ', d.lastname),
        CASE
          WHEN p.idusers IS NOT NULL AND p.is_deleted = FALSE THEN CONCAT(p.firstname, ' ', p.lastname)
          ELSE a.patient_name
        END,
        r.paymentstatus, 
        r.total_paid
      ORDER BY a.date DESC;
    `;

    const result = await client.query(paymentQuery);

    await client.query('COMMIT');

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No payment records found' });
    }

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
    // Fetch all services linked to the given appointment, excluding soft-deleted entries
    const result = await pool.query(
      `SELECT s.idservice, s.name, s.price
       FROM appointment_services aps
       JOIN service s ON aps.idservice = s.idservice
       JOIN appointment a ON aps.idappointment = a.idappointment
       WHERE aps.idappointment = $1
         AND s.is_deleted = FALSE
         AND a.is_deleted = FALSE`,
      [idappointment]
    );

    const services = result.rows; // contains idservice, name, and price

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
    username, email, password, usertype,
    firstname, lastname, birthdate, contact,
    address, gender, allergies, medicalhistory
  } = req.body;

  console.log("📥 Incoming request to update user:", req.body);

  // ✅ Basic validation
  if (!username || !email || !firstname || !lastname || !usertype) {
    console.error("❌ Required fields missing:", req.body);
    return res.status(400).json({ message: 'Required fields missing' });
  }

  const validUsertypes = ['patient', 'dentist', 'admin'];
  if (!validUsertypes.includes(usertype.toLowerCase())) {
    console.error("❌ Invalid usertype:", usertype);
    return res.status(400).json({ message: 'Invalid usertype' });
  }

  try {
    // 1️⃣ Fetch existing user
    let existingUser;
    try {
      const userResult = await pool.query('SELECT * FROM users WHERE idusers = $1', [userId]);
      if (userResult.rows.length === 0) {
        console.warn(`⚠️ User not found — ID: ${userId}`);
        return res.status(404).json({ message: 'User not found' });
      }
      existingUser = userResult.rows[0];
      console.log("✅ Existing user fetched:", existingUser);
    } catch (err) {
      console.error('❌ Error fetching user:', err.message);
      return res.status(500).json({ message: 'Database error fetching user', error: err.message });
    }

    // 2️⃣ Check unique username
    try {
      const usernameCheck = await pool.query(
        'SELECT * FROM users WHERE username = $1 AND idusers != $2 AND is_deleted = FALSE',
        [username, userId]
      );
      if (usernameCheck.rows.length > 0) {
        console.warn(`⚠️ Username already exists: ${username}`);
        return res.status(409).json({ message: 'Username already exists' });
      }
    } catch (err) {
      console.error('❌ Error checking username uniqueness:', err.message);
      return res.status(500).json({ message: 'Database error checking username', error: err.message });
    }

    // 3️⃣ Check unique email
    try {
      const emailCheck = await pool.query(
        'SELECT * FROM users WHERE email = $1 AND idusers != $2 AND is_deleted = FALSE',
        [email, userId]
      );
      if (emailCheck.rows.length > 0) {
        console.warn(`⚠️ Email already exists: ${email}`);
        return res.status(409).json({ message: 'Email already exists' });
      }
    } catch (err) {
      console.error('❌ Error checking email uniqueness:', err.message);
      return res.status(500).json({ message: 'Database error checking email', error: err.message });
    }

    // 4️⃣ Handle password hashing if changed
    let hashedPassword = existingUser.password;
    if (password && !(await bcrypt.compare(password, existingUser.password))) {
      try {
        hashedPassword = await bcrypt.hash(password, 10);
        console.log("🔐 Password hashed successfully");
      } catch (err) {
        console.error('❌ Error hashing password:', err.message);
        return res.status(500).json({ message: 'Error hashing password', error: err.message });
      }
    }

    // 5️⃣ Update user
    let updatedUser;
    try {
      const updateQuery = `
        UPDATE users
        SET username=$1, email=$2, password=$3, usertype=$4,
            firstname=$5, lastname=$6, birthdate=$7, contact=$8,
            address=$9, gender=$10, allergies=$11, medicalhistory=$12,
            updated_at=NOW()
        WHERE idusers=$13 RETURNING *;
      `;
      const values = [
        username, email, hashedPassword, usertype.toLowerCase(),
        firstname, lastname, birthdate, contact, address, gender,
        allergies, medicalhistory, userId
      ];
      const result = await pool.query(updateQuery, values);
      updatedUser = result.rows[0];
      console.log("✅ User updated successfully:", updatedUser);
    } catch (err) {
      console.error('❌ Error updating user:', err.message);
      return res.status(500).json({ message: 'Database error updating user', error: err.message });
    }

// 6️⃣ Prepare undo changes
const changes = { idusers: existingUser.idusers }; // include primary key
const changedFields = [];

['username','email','usertype','firstname','lastname','birthdate','contact','address','gender','allergies','medicalhistory'].forEach(field => {
  if (existingUser[field]?.toString() !== updatedUser[field]?.toString()) {
    changes[field] = existingUser[field]; // old value for undo
    changedFields.push(field);
  }
});

    
// 🛑 If no changes, skip logging and return early
if (changedFields.length === 0) {
  console.log("⚠️ No visible changes — skipping activity log");
  return res.status(200).json({ message: 'No changes detected', user: updatedUser });
}
const description = changedFields.length > 0
  ? `Updated user ${firstname} ${lastname} (${changedFields.join(', ')})`
  : `Updated user ${firstname} ${lastname} (no visible changes)`;

// 7️⃣ Log activity with proper undo_data structure
try {
  console.log("🪵 Logging activity...");
 await logActivity(adminId, 'EDIT', 'users', userId, description, {
  primary_key: 'idusers',
  table: 'users',     // optional but keeps logs uniform
  data: changes
});
  console.log("✅ Activity logged successfully for user ID:", userId);
} catch (err) {
  console.error('❌ Error logging activity:', err.message);
}

console.log("🚀 Returning success response");
return res.status(200).json({ message: 'User updated successfully', user: updatedUser });

  } catch (error) {
    console.error('💥 Unexpected error updating user:', error.message);
    return res.status(500).json({ message: 'Unexpected error updating user', error: error.message });
  }
});

app.post('/api/activity_logs/undo/:logId', async (req, res) => {
  const logId = req.params.logId;
  const adminId = req.body.admin_id;

  try {
    console.log(`🟦 Undo request received — logId: ${logId}, adminId: ${adminId}`);

    // 1️⃣ Fetch the activity log
    const logResult = await pool.query('SELECT * FROM activity_logs WHERE id = $1', [logId]);
    if (!logResult.rows.length) {
      return res.status(404).json({ message: 'Activity log not found' });
    }

    const log = logResult.rows[0];
    console.log("✅ Activity log fetched:", log);

    if (log.is_undone) return res.status(400).json({ message: 'This action has already been undone' });
    if (log.action === 'UNDO') return res.status(400).json({ message: 'Cannot undo an UNDO action' });

    // 2️⃣ Parse undo_data
    const undoData = typeof log.undo_data === 'string' ? JSON.parse(log.undo_data) : log.undo_data;
    if (!undoData) return res.status(400).json({ message: 'Undo data not available' });

    console.log("📦 Parsed undo data:", undoData);

    // 3️⃣ Perform undo depending on action
    if (log.action === 'EDIT') {
      console.log("✏️ Undoing EDIT (restoring previous data)...");

      // 🧩 Multi-table (appointment + appointment_services)
      if (undoData.data && undoData.data.appointment && undoData.data.appointment_services) {
        const appointmentData = undoData.data.appointment;
        const appointmentServicesData = undoData.data.appointment_services;

        const appFields = Object.keys(appointmentData);
        const appValues = Object.values(appointmentData);
        const setClause = appFields.map((f, idx) => `${f} = $${idx + 1}`).join(', ');
        const updateQuery = `UPDATE appointment SET ${setClause}, updated_at = NOW() WHERE ${undoData.primary_key} = $${appFields.length + 1}`;
        await pool.query(updateQuery, [...appValues, appointmentData[undoData.primary_key]]);
        console.log(`✅ Appointment table reverted for ID ${appointmentData[undoData.primary_key]}`);

        // --- Appointment_services table update ---
        await pool.query(`DELETE FROM appointment_services WHERE ${undoData.primary_key} = $1`, [appointmentData[undoData.primary_key]]);
        console.log("🧹 Cleared existing services for appointment", appointmentData[undoData.primary_key]);

        for (const serviceRow of appointmentServicesData) {
          const fields = Object.keys(serviceRow);
          const values = Object.values(serviceRow);
          const placeholders = fields.map((_, idx) => `$${idx + 1}`).join(', ');
          const insertQuery = `INSERT INTO appointment_services (${fields.join(', ')}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;
          await pool.query(insertQuery, values);
        }
        console.log(`✅ Reinserted ${appointmentServicesData.length} services for appointment ${appointmentData[undoData.primary_key]}`);

      } else if (undoData.table && undoData.data) {
        console.log("🧱 Performing single-table undo for EDIT...");
       const record = undoData.data; // single-table undo
const fields = Object.keys(record).filter(f => f !== 'updated_at'); // exclude updated_at
const values = fields.map(f => record[f]);
const setClause = fields.map((f, idx) => `${f} = $${idx + 1}`).join(', ');
const query = `UPDATE ${undoData.table} SET ${setClause}, updated_at = NOW() WHERE ${undoData.primary_key} = $${fields.length + 1}`;
await pool.query(query, [...values, record[undoData.primary_key]]);
console.log(`✅ Restored record in ${undoData.table} to match undo data`);
      } else {
        console.warn("⚠️ Unknown undoData format for EDIT action. Skipping...");
      }

    } else if (log.action === 'DELETE') {
      console.log("♻️ Undoing DELETE (restoring soft-deleted record)...");

      const tableName = undoData.table;
      const primaryKey = undoData.primary_key;
      const data = undoData.data;

      if (!tableName || !primaryKey || !data) {
        return res.status(400).json({ message: 'Incomplete undo data for DELETE action' });
      }

      // --- Multi-table DELETE (appointment + services) ---
      if (data.appointment && data.appointment_services) {
        const recordId = data.appointment[primaryKey];
        console.log(`🔹 Restoring appointment ID ${recordId} with services`);

        // Restore main appointment
        await pool.query(
          `UPDATE ${tableName} SET is_deleted = FALSE, deleted_at = NULL, updated_at = NOW() WHERE ${primaryKey} = $1`,
          [recordId]
        );
        console.log(`✅ Appointment ${recordId} restored`);

        // Restore services
        if (Array.isArray(data.appointment_services) && data.appointment_services.length) {
          console.log(`🔹 Restoring ${data.appointment_services.length} services for appointment ${recordId}`);
          for (const svc of data.appointment_services) {
            const fields = Object.keys(svc);
            const values = Object.values(svc);
            const placeholders = fields.map((_, idx) => `$${idx + 1}`).join(', ');
            const query = `INSERT INTO appointment_services (${fields.join(', ')}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;
            await pool.query(query, values);
            console.log(`   🔹 Restored service ${svc.idservice}`);
          }
        } else {
          console.log("⚠️ No services to restore");
        }

      // --- Single-table DELETE ---
      } else {
        const recordId = data[primaryKey] || (data.appointment && data.appointment[primaryKey]);
        if (!recordId) return res.status(400).json({ message: 'Primary key not found in undo data' });

        console.log(`🔹 Restoring single appointment ID ${recordId}`);

        const recordData = data.appointment ? data.appointment : data;
const fields = Object.keys(recordData).filter(f => f !== 'updated_at'); // exclude updated_at
const values = fields.map(f => recordData[f]);
const setClause = fields.map((f, idx) => `${f} = $${idx + 1}`).join(', ');
const query = `UPDATE ${tableName} SET ${setClause}, updated_at = NOW() WHERE ${primaryKey} = $${fields.length + 1}`;
await pool.query(query, [...values, recordId]);
console.log(`✅ Appointment ${recordId} restored`);

      }

    } else if (log.action === 'ADD') {
      console.log("🗑️ Undoing ADD (soft-deleting new record)...");
      const tableName = undoData.table || log.table_name;
      const primaryKey = undoData.primary_key || 'id';
      const data = undoData.data;
      const recordId = log.record_id || data?.[primaryKey];

      if (!recordId) {
        return res.status(400).json({ message: 'Missing record ID for undoing ADD' });
      }

      const query = `
        UPDATE ${tableName}
        SET is_deleted = TRUE, deleted_at = NOW(), updated_at = NOW()
        WHERE ${primaryKey} = $1
      `;
      await pool.query(query, [recordId]);
      console.log(`✅ Undo ADD completed for ${tableName} record ${recordId}`);
    } else {
      console.warn(`⚠️ Unknown action type (${log.action}). No undo performed.`);
    }

    // 4️⃣ Mark as undone
    await pool.query(
      `UPDATE activity_logs SET is_undone = TRUE, undone_at = NOW() WHERE id = $1`,
      [logId]
    );

    // 5️⃣ Log this undo action
    await logActivity(
      adminId || null,
      'UNDO',
      log.table_name,
      log.record_id,
      `Undid ${log.action} activity log ID ${logId}`,
      null
    );

    console.log(`✅ Undo completed successfully for log ID ${logId}`);
    return res.status(200).json({ message: 'Undo successful' });

  } catch (error) {
    console.error('💥 Unexpected error performing undo:', error);
    return res.status(500).json({ message: 'Unexpected error performing undo', error: error.message });
  }
});

app.get('/api/app/records', async (req, res) => {
  const query = `
    SELECT 
      p.idusers AS idpatient, -- Patient ID
      r.idrecord,             -- Record ID
      CONCAT(p.firstname, ' ', p.lastname) AS patientFullname, -- Full name of patient
      CONCAT(d.firstname, ' ', d.lastname) AS dentistFullname, -- Full name of dentist
      r.treatment_notes,      -- Notes about the treatment
      r.paymentstatus,        -- Payment status (unpaid, partial, paid)
      r.idappointment,        -- Associated appointment ID
      a.date AS appointmentDate, -- Appointment date
      COALESCE(
        (
          SELECT STRING_AGG(s.name, ', ') -- List of services for this appointment
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
            AND s.is_deleted = FALSE
        ), ''
      ) AS services,
      COALESCE(
        (
          SELECT SUM(s.price) -- Total price of services for this appointment
          FROM appointment_services aps
          JOIN service s ON aps.idservice = s.idservice
          WHERE aps.idappointment = r.idappointment
            AND s.is_deleted = FALSE
        ), 0
      ) AS totalPrice
    FROM users p
    LEFT JOIN records r 
      ON r.idpatient = p.idusers AND r.is_deleted = FALSE
    LEFT JOIN users d 
      ON r.iddentist = d.idusers AND d.is_deleted = FALSE
    LEFT JOIN appointment a 
      ON r.idappointment = a.idappointment AND a.is_deleted = FALSE
    WHERE p.usertype = 'patient' AND p.is_deleted = FALSE
    ORDER BY r.idrecord DESC NULLS LAST;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No records found' });
    }

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
    adminId
  } = req.body;

  // ✅ Validation
  if (!username || !email || !password || !usertype || !firstname || !lastname) {
    console.error("❌ Missing required fields in request body");
    return res.status(400).json({ message: 'Required fields missing' });
  }

  try {
    console.log("🔍 Checking for existing username/email...");
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE (username = $1 OR email = $2) AND is_deleted = FALSE',
      [username, email]
    );

    if (userCheck.rows.length > 0) {
      console.warn("⚠️ Username or email already exists");
      return res.status(409).json({ message: 'Username or email already exists' });
    }

    console.log("🔐 Hashing password...");
    const hashedPassword = await bcrypt.hash(password, 10);

    console.log("📝 Inserting new user...");
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
    console.log("✅ User inserted successfully:", newUser.username);

    // 🧾 Log admin activity
    try {
      console.log("🪵 Logging admin activity...");
   await logActivity(
  adminId || null,
  'ADD',
  'users',
  newUser.idusers,
  `Added new ${usertype} user: ${firstname} ${lastname} (username: ${username})`,
  {
    primary_key: 'idusers',
    table: 'users', // ✅ add table name for uniformity
    data: {
      idusers: newUser.idusers,
      username: newUser.username,
      email: newUser.email,
      usertype: newUser.usertype
    }
  }
);

      console.log("✅ Activity logged successfully");
    } catch (logError) {
      console.error("❌ Error logging admin activity:", logError);
    }

    return res.status(201).json({
      message: 'User created successfully',
      user: newUser,
    });

  } catch (error) {
    if (error.code === '23505') {
      console.warn("⚠️ Duplicate entry detected:", error.detail);
      return res.status(409).json({ message: 'Username or email already exists' });
    }
    console.error("❌ Error adding user:", error);
    return res.status(500).json({ message: 'Error adding user', error: error.message });
  }
});

app.get('/api/app/appointments/search', async (req, res) => { 
  const { dentist, patient, startDate, endDate } = req.query;

  // ✅ Prepare dynamic conditions for filtering
  let conditions = ['is_deleted = FALSE']; // Always exclude soft-deleted appointments
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
    conditions.push(`DATE(date AT TIME ZONE 'Asia/Manila') BETWEEN $${values.length + 1} AND $${values.length + 2}`);
    values.push(startDate, endDate);
  }

  // Build WHERE clause dynamically
  const whereClause = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  // ✅ Final query with optional filters, sorted by date ascending
  const query = `SELECT * FROM appointment ${whereClause} ORDER BY date ASC`;

  try {
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    // ✅ Return filtered appointments
    return res.status(200).json({ appointments: result.rows });
  } catch (err) {
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});


// ✅ Get all active dentists (users with usertype = 'dentist')
app.get('/api/app/dentists', async (req, res) => {
  const query = `
    SELECT idusers, firstname, lastname
    FROM users
    WHERE usertype = 'dentist'
      AND is_deleted = FALSE
    ORDER BY firstname, lastname
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No dentists found' });
    }

    return res.status(200).json({
      dentists: result.rows
    });
  } catch (err) {
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

// ✅ Get all active users from the database
app.get('/api/app/users', async (req, res) => {
  const query = `
    SELECT *
    FROM users
    WHERE is_deleted = FALSE
    ORDER BY firstname, lastname
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    // Format birthdate to YYYY-MM-DD
    const formattedRows = result.rows.map(user => ({
      ...user,
      birthdate: user.birthdate
        ? user.birthdate.toISOString().split('T')[0]
        : null
    }));

    return res.status(200).json({ records: formattedRows });
  } catch (err) {
    console.error('Error fetching users:', err.message);
    return res.status(500).json({ message: 'Error fetching users', error: err.message });
  }
});


// ✅ Get all active users from the database
app.get('/api/website/users', async (req, res) => {
  const query = `
    SELECT *
    FROM users
    WHERE is_deleted = FALSE
    ORDER BY firstname, lastname
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No users found' });
    }

    // Format birthdate to YYYY-MM-DD
    const users = result.rows.map(user => ({
      ...user,
      birthdate: user.birthdate ? user.birthdate.toISOString().split('T')[0] : null
    }));

    return res.status(200).json({ records: users });
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

// ✅ Update a specific appointment (with full undo-ready activity log)
app.put('/api/website/appointments/:id', async (req, res) => {
  const idappointment = req.params.id;
  const { idpatient, iddentist, date, status, notes, idservice, patient_name, adminId } = req.body;

  console.log("📥 Incoming request to update appointment:", req.body);
  console.log("🧑 Admin ID received:", adminId);

  // 0️⃣ Basic validation
  if (!iddentist || !idservice || !Array.isArray(idservice) || idservice.length === 0) {
    return res.status(400).json({ message: 'iddentist and idservice array are required.' });
  }
  if (!idpatient && !patient_name) {
    return res.status(400).json({ message: 'Either idpatient or patient_name is required.' });
  }

  try {
    // 1️⃣ Fetch existing appointment
    const existingResult = await pool.query(
      'SELECT * FROM appointment WHERE idappointment = $1',
      [idappointment]
    );
    if (existingResult.rows.length === 0) {
      return res.status(404).json({ message: 'Appointment not found' });
    }
    const existingAppointment = existingResult.rows[0];
    console.log("📝 Existing appointment:", existingAppointment);

    // 2️⃣ Fetch existing services
    const existingServicesResult = await pool.query(
      'SELECT * FROM appointment_services WHERE idappointment = $1',
      [idappointment]
    );
    const existingServices = existingServicesResult.rows;
    console.log("📝 Existing services:", existingServices.map(s => s.idservice));

    // 3️⃣ Update appointment
    let updateQuery, queryParams;
    if (idpatient) {
      updateQuery = `
        UPDATE appointment
        SET idpatient = $1, iddentist = $2, date = $3, status = $4, notes = $5, patient_name = NULL, updated_at = NOW()
        WHERE idappointment = $6 RETURNING *;
      `;
      queryParams = [
        idpatient,
        iddentist,
        date || existingAppointment.date,
        status || existingAppointment.status,
        notes || existingAppointment.notes,
        idappointment
      ];
    } else {
      updateQuery = `
        UPDATE appointment
        SET idpatient = NULL, iddentist = $1, date = $2, status = $3, notes = $4, patient_name = $5, updated_at = NOW()
        WHERE idappointment = $6 RETURNING *;
      `;
      queryParams = [
        iddentist,
        date || existingAppointment.date,
        status || existingAppointment.status,
        notes || existingAppointment.notes,
        patient_name,
        idappointment
      ];
    }

    const updatedResult = await pool.query(updateQuery, queryParams);
    const updatedAppointment = updatedResult.rows[0];
    console.log("📝 Updated appointment:", updatedAppointment);

    // 4️⃣ Replace services
    await pool.query('DELETE FROM appointment_services WHERE idappointment = $1', [idappointment]);
    const insertPromises = idservice.map(sid =>
      pool.query('INSERT INTO appointment_services (idappointment, idservice) VALUES ($1, $2)', [idappointment, sid])
    );
    await Promise.all(insertPromises);
    console.log("📝 Services replaced:", idservice);

    // 5️⃣ Prepare changes for activity log
    const compareFields = ['idpatient', 'iddentist', 'date', 'status', 'notes', 'patient_name'];
    const changes = { idappointment: existingAppointment.idappointment };
    const changedFields = [];

    compareFields.forEach(f => {
      const oldVal = existingAppointment[f];
      const newVal = updatedAppointment[f];
      console.log(`🔍 Comparing field "${f}": old="${oldVal}", new="${newVal}"`);

      if ((oldVal ?? '').toString() !== (newVal ?? '').toString()) {
        changes[f] = oldVal;
        changedFields.push(f);
      }
    });

    // Services comparison
    const oldServiceIds = existingServices.map(s => Number(s.idservice)).sort();
    const newServiceIds = idservice.map(Number).sort();
    console.log("🔍 Comparing services: old=", oldServiceIds, "new=", newServiceIds);
    if (JSON.stringify(oldServiceIds) !== JSON.stringify(newServiceIds)) {
      changes['services'] = oldServiceIds;
      changedFields.push('services');
    }

    console.log("🪵 Final changes object for logging:", changes);
    console.log("🪵 Changed fields array:", changedFields);
    console.log("🧑 Admin ID before logging:", adminId);
// 5️⃣ Prepare undo-ready data for activity log
const undoData = {
  primary_key: 'idappointment',
  table: 'appointment',
  data: {
    appointment: {
      idappointment: existingAppointment.idappointment,
      idpatient: existingAppointment.idpatient,
      iddentist: existingAppointment.iddentist,
      date: existingAppointment.date,
      status: existingAppointment.status,
      notes: existingAppointment.notes,
      patient_name: existingAppointment.patient_name
    },
    appointment_services: existingServices.map(s => ({
      idappointment: s.idappointment,
      idservice: s.idservice
    }))
  }
};

    // 6️⃣ Log activity if there were changes
  if (changedFields.length > 0) {
  if (!adminId) console.warn("⚠️ Admin ID is missing; cannot log activity!");
  else {
    try {
      await logActivity(
        adminId,
        'EDIT',
        'appointment',
        idappointment,
        `Updated appointment ID ${idappointment} (${changedFields.join(', ')})`,
        undoData // <-- use the correctly structured undo data
      );
      console.log("✅ Activity logged successfully.");
    } catch (logErr) {
      console.error("❌ Error logging activity:", logErr.message);
    }
  }
}
 else {
      console.log("⚠️ No visible changes detected — skipping activity log");
    }

    // ✅ Return response
    return res.status(200).json({
      message: 'Appointment updated successfully',
      appointment: updatedAppointment,
      servicesUpdated: idservice
    });

  } catch (error) {
    console.error('💥 Unexpected error updating appointment:', error.message);
    return res.status(500).json({ message: 'Error updating appointment', error: error.message });
  }
});


// ✅ Get all active patients (users with usertype = 'patient')
app.get('/api/app/patients', async (req, res) => {
  const query = `
    SELECT idusers, firstname, lastname
    FROM users
    WHERE usertype = 'patient'
      AND is_deleted = FALSE
    ORDER BY firstname, lastname
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No patients found' });
    }

    return res.status(200).json({
      patients: result.rows
    });
  } catch (err) {
    console.error('Error fetching patients:', err.message);
    return res.status(500).json({ message: 'Error fetching patients', error: err.message });
  }
});

// ✅ Get all appointments, sorted by date ascending
app.get('/api/app/appointments', async (req, res) => {
  const fetchQuery = `
    SELECT *
    FROM appointment
    WHERE is_deleted = FALSE
    ORDER BY date ASC, idappointment ASC
  `;

  try {
    const result = await pool.query(fetchQuery);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    return res.status(200).json({ appointments: result.rows });
  } catch (err) {
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
  }
});

// ✅ Get all appointments, sorted by date ascending
app.get('/api/website/appointments', async (req, res) => {
  const fetchQuery = `
    SELECT *
    FROM appointment
    WHERE is_deleted = FALSE
    ORDER BY date ASC, idappointment ASC
  `;

  try {
    const result = await pool.query(fetchQuery);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No appointments found' });
    }

    return res.status(200).json({ appointments: result.rows });
  } catch (err) {
    console.error('Error fetching appointments:', err.message);
    return res.status(500).json({ message: 'Error fetching appointments', error: err.message });
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

// Get profile route (excluding soft-deleted users)
app.get('/api/app/profile', authenticateToken, async (req, res) => {
  try {
    // Fetch user based on authenticated userId and is not soft-deleted
    const getQuery = 'SELECT * FROM users WHERE idusers = $1 AND is_deleted = FALSE';
    const result = await pool.query(getQuery, [req.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found or has been deleted" });
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
app.post('/api/website/services', async (req, res) => {
  const { name, description, price, category, adminId } = req.body;

  // ✅ Validate inputs
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }
  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }
  if (!category || typeof category !== 'string' || category.trim().length === 0) {
    return res.status(400).json({ message: 'Category is required and must be a non-empty string.' });
  }

  try {
    console.log('📝 Inserting new service...');
    const insertQuery = `
      INSERT INTO service (name, description, price, category)
      VALUES ($1, $2, $3, $4)
      RETURNING idservice, name, description, price, category
    `;
    const result = await pool.query(insertQuery, [
      name.trim(),
      description || null,
      parseFloat(price),
      category.trim()
    ]);

    const service = result.rows[0];
    console.log('✅ Service added:', service);

    // 🧾 Log admin activity
    try {
      console.log('🪵 Logging admin activity for service addition...');
  const primaryKey = 'idservice';
await logActivity(
  adminId || null,
  'ADD',
  'service',
  service.idservice,
  `Added new service: ${service.name} (${service.category})`,
  {
    primary_key: 'idservice',
    table: 'service',
    data: {
      idservice: service.idservice,
      name: service.name,
      description: service.description,
      price: service.price,
      category: service.category
    }
  }
);
      console.log('✅ Activity logged successfully for service ID:', service.idservice);
    } catch (logError) {
      console.error('❌ Error logging admin activity:', logError);
    }

    // 🔔 Send notifications to users with FCM tokens
    const tokensResult = await pool.query(`SELECT fcm_token FROM users WHERE fcm_token IS NOT NULL`);
    const tokens = tokensResult.rows.map(r => r.fcm_token).filter(t => t && t.trim().length > 0);

    if (tokens.length === 0) {
      console.log('⚠️ No users with FCM tokens.');
      return res.status(201).json({ message: 'Service added successfully', service, notificationSent: false });
    }

    const notificationPayload = {
      notification: {
        title: '🦷 New Dental Service Available',
        body: `${service.name} has been added to our services list!`
      },
      data: { serviceId: service.idservice.toString(), serviceName: service.name },
      android: { notification: { channelId: 'appointment_channel_id', priority: 'high' } }
    };

    const MAX_BATCH = 500;
    let totalSuccess = 0;

    for (let i = 0; i < tokens.length; i += MAX_BATCH) {
      const batch = tokens.slice(i, i + MAX_BATCH);
      const multicastMessage = { tokens: batch, ...notificationPayload };
      const response = await admin.messaging().sendEachForMulticast(multicastMessage);

      totalSuccess += response.successCount;
      console.log(`📩 Batch sent: ${response.successCount}/${batch.length} successes`);
      response.responses.forEach((resp, idx) => {
        if (!resp.success) console.warn(`❌ Failed for token ${batch[idx]}:`, resp.error?.message);
      });
    }

    return res.status(201).json({
      message: 'Service added and notifications sent successfully',
      service,
      notificationSent: true,
      totalRecipients: tokens.length,
      successfulNotifications: totalSuccess
    });

  } catch (err) {
    console.error('❌ Error adding service or sending notifications:', err.stack);
    return res.status(500).json({ message: 'Failed to add service or notify users', error: err.message });
  }
});

// Get all services route (excluding soft-deleted ones)
app.get('/api/app/services', async (req, res) => {
  // SQL query to select all services that are not soft-deleted
  const query = 'SELECT * FROM service WHERE is_deleted = FALSE';

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

// Get all services route (excluding soft-deleted ones)
app.get('/api/website/services', async (req, res) => {
  // SQL query to select all services that are not soft-deleted
  const query = 'SELECT * FROM service WHERE is_deleted = FALSE';

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

// Get all services route (excluding soft-deleted)
app.get('/api/website/services', async (req, res) => {
  const query = 'SELECT * FROM service WHERE is_deleted = FALSE';

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No services found' });
    }

    return res.status(200).json({
      services: result.rows
    });
  } catch (err) {
    console.error('Error fetching services:', err.message);
    return res.status(500).json({ message: 'Error fetching services', error: err.message });
  }
});

// Route to update an existing service
app.put('/api/website/services/:id', async (req, res) => {
  const serviceId = req.params.id;
  const adminId = req.body.admin_id;
  const { name, description, price } = req.body;

  // ✅ Validate name
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ message: 'Name is required and must be a non-empty string.' });
  }

  // ✅ Validate price
  if (price === undefined || isNaN(price)) {
    return res.status(400).json({ message: 'Price is required and must be a valid number.' });
  }

  try {
    // 1️⃣ Fetch existing service
    const serviceResult = await pool.query(
      'SELECT * FROM service WHERE idservice = $1 AND is_deleted = FALSE',
      [serviceId]
    );
    if (serviceResult.rows.length === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    const existingService = serviceResult.rows[0];

    // 2️⃣ Update service
    const updateQuery = `
      UPDATE service
      SET name = $1, description = $2, price = $3, updated_at = NOW()
      WHERE idservice = $4
      RETURNING idservice, name, description, price, category
    `;
    const updateResult = await pool.query(updateQuery, [
      name.trim(),
      description || null,
      parseFloat(price),
      serviceId
    ]);

    const updatedService = updateResult.rows[0];

   // 3️⃣ Compare fields for changes
const changes = { idservice: existingService.idservice }; // <-- include PK

['name', 'description', 'price'].forEach(field => {
  if (existingService[field]?.toString() !== updatedService[field]?.toString()) {
    changes[field] = existingService[field]; // old value for undo
  }
});


    // 4️⃣ Log activity if there were changes
    try {
      if (Object.keys(changes).length > 0) {
        const undoData = {
          primary_key: 'idservice',
          table: 'service',
          data: changes
        };

        await logActivity(
          adminId || null,
          'EDIT',
          'service',
          serviceId,
          `Updated service ${existingService.name} (fields: ${Object.keys(changes).join(', ')})`,
          undoData
        );

        console.log('🪵 Activity logged successfully for service update.');
      } else {
        console.log('⚠️ No changes detected, skipping activity log.');
      }
    } catch (logErr) {
      console.error('❌ Error logging activity:', logErr.message);
    }

    // ✅ Return response
    return res.status(200).json({
      message: 'Service updated successfully',
      service: updatedService
    });

  } catch (err) {
    console.error('💥 Unexpected error updating service:', err.message);
    return res.status(500).json({ message: 'Error updating service', error: err.message });
  }
});

// Delete Service
// This endpoint deletes a specific service from the database using its ID.
// If the service doesn't exist, it returns a 404 error.
// If the service is linked to other records (in use), it returns an error message.
app.delete('/api/website/services/:id', async (req, res) => {
  const serviceId = req.params.id;
  const adminId = req.userId; // From auth middleware

  try {
    // 1️⃣ Get existing service data before deleting
    const existingServiceResult = await pool.query(
      `SELECT * FROM service WHERE idservice = $1 AND is_deleted = FALSE`,
      [serviceId]
    );

    if (existingServiceResult.rows.length === 0) {
      return res.status(404).json({ message: 'Service not found or already deleted' });
    }

    const existingService = existingServiceResult.rows[0];

    // 2️⃣ Soft delete the service
    const result = await pool.query(
      `UPDATE service
       SET is_deleted = TRUE,
           deleted_at = NOW(),
           updated_at = NOW()
       WHERE idservice = $1
       RETURNING *`,
      [serviceId]
    );

  await logActivity(
  adminId,
  'DELETE',
  'service',
  serviceId,
  `Deleted service ${existingService.name}`,
  {
    primary_key: 'idservice',
    table: 'service',
    data: {
      ...existingService,
      is_deleted: true,
      deleted_at: new Date().toISOString()
    }
  }
);
    return res.status(200).json({
      message: 'Service soft-deleted successfully',
      service: result.rows[0]
    });

  } catch (err) {
    console.error('💥 Error deleting service:', err.message);
    return res.status(500).json({ message: 'Error deleting service', error: err.message });
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
    // 1️⃣ Get existing user data before deleting
    const existingUserResult = await pool.query(
      `SELECT * FROM users WHERE idusers = $1 AND is_deleted = FALSE`,
      [userId]
    );

    if (existingUserResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found or already deleted' });
    }

    const existingUser = existingUserResult.rows[0];

    // 2️⃣ Soft delete the user
    const result = await pool.query(
      `UPDATE users
       SET is_deleted = TRUE,
           deleted_at = NOW(),
           updated_at = NOW()
       WHERE idusers = $1
       RETURNING *`,
      [userId]
    );

    // 3️⃣ Log activity (with undo-ready data)
    await logActivity(
      adminId,
      'DELETE',
      'users',
      userId,
      `Deleted user ${existingUser.firstname} ${existingUser.lastname}`,
      {
        primary_key: 'idusers',
        table: 'users',
        data: {
          ...existingUser,
          is_deleted: true,
          deleted_at: new Date().toISOString()
        }
      }
    );

    // 4️⃣ Respond to client
    return res.status(200).json({
      message: 'User soft-deleted successfully',
      user: result.rows[0]
    });

  } catch (err) {
    console.error('💥 Error deleting user:', err.message);
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






































