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
  process.env.SECOND_FRONTEND_URL,    // Local frontend (for development/testing)
  process.env.THIRD_FRONTEND_URL 
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

// 🔥 Firebase Admin setup

// Check if the env variable exists
if (!process.env.FIREBASE_ACCOUNT) {
  throw new Error("FIREBASE_ACCOUNT env variable is missing!");
}

// Parse the service account JSON
const serviceAccount = JSON.parse(process.env.FIREBASE_ACCOUNT);

// Replace literal '\n' with real newlines in the private key
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

// Log to confirm
console.log('FIREBASE_ACCOUNT:', process.env.FIREBASE_ACCOUNT ? 'Exists' : 'Not set');

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
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

// 🕒  job to check upcoming appointments and notify logged-in users
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
fs.writeFileSync(keyFilePath, process.env.GOOGLE_CLOUD_ACCOUNT);

// Google Cloud Storage client setup using the key file
const storage = new Storage({ keyFilename: keyFilePath });

// Reference a specific bucket in Google Cloud Storage
// This bucket ('toothpix-models') will store your uploaded files
const bucket = storage.bucket('toothpix-models');

// 📌 PUBLIC route to upload "BEFORE" dental 3D model (GLTF + optional BIN)
app.post(
  '/api/uploadModel/before',
  upload.fields([
    { name: 'gltf', maxCount: 1 },
    { name: 'bin', maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const idrecord = req.body.idrecord; // Record ID from frontend
      if (!idrecord) {
        return res.status(400).json({ success: false, error: 'Missing record ID' });
      }

      // -------- Upload GLTF file --------
      if (!req.files['gltf'] || req.files['gltf'].length === 0) {
        return res.status(400).json({ success: false, error: 'GLTF file is required' });
      }

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

      // -------- Store in PostgreSQL --------
      await pool.query(
        `INSERT INTO dental_models (idrecord, before_model_url, before_model_bin_url, before_uploaded_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (idrecord) DO UPDATE
         SET before_model_url = EXCLUDED.before_model_url,
             before_model_bin_url = EXCLUDED.before_model_bin_url,
             before_uploaded_at = NOW()`,
        [idrecord, gltfPath, binPath]
      );

      // ✅ Success response
      return res.json({
        success: true,
        message: 'Before model uploaded successfully',
        gltfPath,
        binPath,
      });
    } catch (err) {
      console.error('Upload error:', err);
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

    // If no record exists, return null model (not error)
    if (result.rows.length === 0) {
      console.log(`⚠️ No model found for record ${idrecord}`);
      return res.json({ model: null });
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

    // ✅ Return in Flutter-compatible structure
    return res.json({
      model: {
        id: row.id,
        idrecord: row.idrecord,
        gltfUrl: gltfSignedUrl,
        binUrl: binSignedUrl,
      },
    });

  } catch (err) {
    console.error('❌ Error fetching model:', err.message);
    return res.status(500).json({
      model: null,
      error: err.message,
    });
  }
});

// 📌 Generate payment report for all records (excluding deleted users, services, and appointments)
app.get('/api/reports/payments', async (req, res) => {
  const query = `
 SELECT   
    r.idrecord,
    CASE 
        WHEN a.idpatient IS NULL OR a.idpatient = 0 THEN a.patient_name
        ELSE CONCAT(p.firstname, ' ', p.lastname)
    END AS patient_name,
    CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,
    a.date AS appointment_date,
    STRING_AGG(s.name, ', ') AS services,       -- Combine all services for that appointment
    SUM(s.price) AS total_price,                -- Total price of all services
    r.total_paid,
    r.paymentstatus
FROM records r
JOIN appointment a 
    ON r.idappointment = a.idappointment 
    AND a.is_deleted = FALSE
LEFT JOIN users p 
    ON a.idpatient = p.idusers 
    AND p.is_deleted = FALSE  -- Patient (if registered)
JOIN users d 
    ON a.iddentist = d.idusers 
    AND d.is_deleted = FALSE  -- Dentist
JOIN appointment_services aps 
    ON aps.idappointment = a.idappointment
JOIN service s 
    ON s.idservice = aps.idservice 
    AND s.is_deleted = FALSE
GROUP BY 
    r.idrecord, 
    a.idpatient,              -- ✅ Added to support the CASE
    a.patient_name, 
    p.firstname, p.lastname, 
    d.firstname, d.lastname, 
    a.date, 
    r.total_paid, 
    r.paymentstatus
ORDER BY 
    LOWER(
      CASE 
        WHEN a.idpatient IS NULL OR a.idpatient = 0 THEN a.patient_name
        ELSE CONCAT(p.firstname, ' ', p.lastname)
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

app.post('/api/unity/dentalmodelteeth/:id', async (req, res) => {
  const model_id = req.params.id;
  const { teeth } = req.body;

  if (!teeth || !Array.isArray(teeth) || teeth.length === 0) {
    return res.status(400).json({ message: 'Teeth data is required.' });
  }

  try {
    const insertQuery = `
      INSERT INTO dental_model_teeth (model_id, tooth_number, tooth_name, status)
      VALUES ($1, $2, $3, $4)
      RETURNING *;
    `;

    const inserted = [];
    for (const tooth of teeth) {
      const { tooth_number, tooth_name, status } = tooth;
      const { rows } = await pool.query(insertQuery, [
        model_id,
        tooth_number,
        tooth_name,
        status,
      ]);
      inserted.push(rows[0]);
    }

    res.status(201).json({
      message: 'All tooth data saved successfully',
      count: inserted.length,
      data: inserted,
    });
  } catch (error) {
    console.error('Error inserting tooth data:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/unity/dentalmodelteeth/:id', async (req, res) => {
  const model_id = req.params.id; // ✅ get model_id from URL

  try {
    const selectQuery = `
      SELECT id, model_id, tooth_number, tooth_name, status, created_at, updated_at
      FROM dental_model_teeth
      WHERE model_id = $1
      ORDER BY tooth_number ASC;
    `;

    const { rows } = await pool.query(selectQuery, [model_id]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'No teeth records found for this model.' });
    }

    res.status(200).json({
      message: 'Tooth records fetched successfully',
      data: rows,
    });
  } catch (error) {
    console.error('Error fetching tooth data:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// API endpoint to fetch all dental records along with appointment and service details (excluding deleted entries)
app.get('/api/reports/records', async (req, res) => {
  const query = `
   SELECT  
    r.idrecord,
    -- Determine patient name
    CASE 
        WHEN a.idpatient IS NOT NULL THEN CONCAT(p.firstname, ' ', p.lastname)
        ELSE a.patient_name
    END AS patient_name,
    -- Dentist's full name from appointment
    CONCAT(d.firstname, ' ', d.lastname) AS dentist_name,
    a.date AS appointment_date,
    STRING_AGG(s.name, ', ') AS services,
    r.treatment_notes
FROM records r
JOIN appointment a 
    ON a.idappointment = r.idappointment 
    AND a.is_deleted = FALSE
LEFT JOIN users p 
    ON p.idusers = a.idpatient 
    AND p.is_deleted = FALSE
LEFT JOIN users d 
    ON d.idusers = a.iddentist 
    AND d.is_deleted = FALSE
JOIN appointment_services aps 
    ON aps.idappointment = a.idappointment
JOIN service s 
    ON s.idservice = aps.idservice 
    AND s.is_deleted = FALSE
WHERE a.status != 'cancelled'
GROUP BY 
    r.idrecord, 
    a.idpatient,
    p.firstname, 
    p.lastname, 
    a.patient_name, 
    d.firstname, 
    d.lastname, 
    a.date, 
    r.treatment_notes
ORDER BY
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
JOIN appointment a 
  ON r.idappointment = a.idappointment 
  AND a.is_deleted = FALSE  -- only active appointments
JOIN users p 
  ON a.idpatient = p.idusers 
  AND p.is_deleted = FALSE  -- only active patients
JOIN users d 
  ON a.iddentist = d.idusers 
  AND d.is_deleted = FALSE  -- only active dentists
LEFT JOIN dental_models rm 
  ON rm.idrecord = r.idrecord
WHERE r.is_deleted = FALSE  -- only active records
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

// API endpoint to fetch top dentists based on completed appointments
app.get('/api/reports/top-dentists', async (req, res) => {
  const query = `
    SELECT 
      a.iddentist,
      CONCAT(u.firstname, ' ', u.lastname) AS fullname,
      COUNT(*) AS patients_helped
    FROM appointment a
    JOIN users u 
      ON u.idusers = a.iddentist 
      AND u.is_deleted = FALSE
    WHERE a.status = 'completed'
      AND a.is_deleted = FALSE
    GROUP BY a.iddentist, fullname
    ORDER BY patients_helped DESC;
  `;

  try {
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No dentist data available" });
    }

    return res.status(200).json({ topDentists: result.rows });
    
  } catch (err) {
    console.error("Error fetching top dentists report:", err.message);
    return res.status(500).json({
      message: "Error fetching top dentists report",
      error: err.message
    });
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



