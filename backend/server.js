const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Connect to SQLite Database
const dbPath = path.join(__dirname, 'complaints.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDB();
    }
});

// Create tables
function initializeDB() {
    db.serialize(() => {
        // Users Table with Reset Token columns
        db.run(`CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            reset_token TEXT,
            token_expiry DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (!err) {
                // Add columns safely if they don't exist
                db.run(`ALTER TABLE Users ADD COLUMN reset_token TEXT`, () => { });
                db.run(`ALTER TABLE Users ADD COLUMN token_expiry DATETIME`, () => { });

                // Create a default demo user if none exists
                db.get(`SELECT id FROM Users WHERE email = ?`, ['user@example.com'], async (err, userRow) => {
                    if (!userRow) {
                        const demoHash = await bcrypt.hash('user123', 10);
                        db.run(`INSERT INTO Users (name, email, password) VALUES (?, ?, ?)`, ['Demo User', 'user@example.com', demoHash]);
                    }
                });

                // Ensure gowtham@gmail.com user exists with password gowtham12345
                db.get(`SELECT id FROM Users WHERE email = ?`, ['gowtham@gmail.com'], async (err, gowthamRow) => {
                    const gowthamHash = await bcrypt.hash('gowtham12345', 10);
                    if (!gowthamRow) {
                        db.run(`INSERT INTO Users (name, email, password) VALUES (?, ?, ?)`, ['Gowtham', 'gowtham@gmail.com', gowthamHash]);
                    } else {
                        db.run(`UPDATE Users SET password = ? WHERE email = ?`, [gowthamHash, 'gowtham@gmail.com']);
                    }
                });
            }
        });

        // Admin Table
        db.run(`CREATE TABLE IF NOT EXISTS Admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            reset_token TEXT,
            token_expiry DATETIME
        )`, (err) => {
            if (!err) {
                db.get(`SELECT * FROM Admin WHERE username = 'admin@gmail.com'`, async (err, row) => {
                    if (!row) {
                        const hash = await bcrypt.hash('admin123', 10);
                        db.run(`INSERT INTO Admin (username, password) VALUES ('admin@gmail.com', ?)`, [hash]);
                    }
                });
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS Complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            description TEXT,
            address TEXT,
            latitude REAL,
            longitude REAL,
            image TEXT,
            status TEXT DEFAULT 'Pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (!err) {
                db.run(`ALTER TABLE Complaints ADD COLUMN incident_date DATE`, () => { });
                db.run(`ALTER TABLE Complaints ADD COLUMN category TEXT DEFAULT 'Other'`, () => { });
                db.run(`ALTER TABLE Complaints ADD COLUMN is_deleted INTEGER DEFAULT 0`, () => { });
            }
        });

        db.run(`CREATE TABLE IF NOT EXISTS Tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id INTEGER,
            latitude REAL,
            longitude REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS ActivityLog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    });
}

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, '../frontend'))); // Adjusted static folder
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

// Configure Multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// ======================= User APIs =======================

// 1. Register User
app.post('/api/register', async (req, res) => {
    const name = (req.body.name || '').trim();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    try {
        const hash = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO Users (name, email, password) VALUES (?, ?, ?)`, [name, email, hash], function (err) {
            if (err) return res.status(400).json({ success: false, message: 'Email already exists or invalid data.' });
            db.run(`INSERT INTO ActivityLog (action) VALUES (?)`, [`New user ${name} registered`]);
            res.json({ success: true, message: 'Registration successful', userId: this.lastID });
        });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// 2. Login User
app.post('/api/login', (req, res) => {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    db.get(`SELECT * FROM Users WHERE LOWER(email) = LOWER(?)`, [email], async (err, row) => {
        if (err || !row) return res.status(401).json({ success: false, message: 'Invalid credentials.' });
        const valid = await bcrypt.compare(password, row.password);
        if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials.' });

        res.json({ success: true, message: 'Login successful', user: { id: row.id, name: row.name, email: row.email } });
    });
});

// 3. Forgot Password
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    const token = crypto.randomBytes(20).toString('hex');
    const expiry = new Date(Date.now() + 3600000).toISOString(); // 1 hour

    // Check user first, if not check admin
    db.get(`SELECT id FROM Users WHERE email = ?`, [email], (err, row) => {
        if (row) {
            db.run(`UPDATE Users SET reset_token = ?, token_expiry = ? WHERE email = ?`, [token, expiry, email], () => {
                res.json({ success: true, message: 'Reset token generated (simulated email)', token });
            });
        } else {
            db.get(`SELECT id FROM Admin WHERE username = ?`, [email], (err, aRow) => {
                if (aRow) {
                    db.run(`UPDATE Admin SET reset_token = ?, token_expiry = ? WHERE username = ?`, [token, expiry, email], () => {
                        res.json({ success: true, message: 'Admin reset token generated', token });
                    });
                } else {
                    res.status(404).json({ success: false, message: 'Email/Username not found' });
                }
            });
        }
    });
});

// 4. Reset Password
app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    const hash = await bcrypt.hash(newPassword, 10);
    const now = new Date().toISOString();

    db.get(`SELECT * FROM Users WHERE reset_token = ? AND token_expiry > ?`, [token, now], (err, row) => {
        if (row) {
            db.run(`UPDATE Users SET password = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?`, [hash, row.id], () => {
                res.json({ success: true, message: 'User password reset successful' });
            });
        } else {
            db.get(`SELECT * FROM Admin WHERE reset_token = ? AND token_expiry > ?`, [token, now], (err, aRow) => {
                if (aRow) {
                    db.run(`UPDATE Admin SET password = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?`, [hash, aRow.id], () => {
                        res.json({ success: true, message: 'Admin password reset successful' });
                    });
                } else {
                    res.status(400).json({ success: false, message: 'Invalid or expired token' });
                }
            });
        }
    });
});


// 5. Submit Complaint
app.post('/api/complaints', upload.single('image'), (req, res) => {
    const { user_id, title, description, address, latitude, longitude, incident_date, category } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const query = `INSERT INTO Complaints (user_id, title, description, address, latitude, longitude, image, status, incident_date, category) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)`;

    db.run(query, [user_id, title, description, address, latitude, longitude, imagePath, incident_date, category || 'Other'], function (err) {
        if (err) return res.status(500).json({ success: false, message: 'Failed to submit complaint.' });
        const cId = this.lastID;
        db.get(`SELECT name FROM Users WHERE id = ?`, [user_id], (e, u) => {
            const name = u ? u.name : 'Unknown';
            db.run(`INSERT INTO ActivityLog (action) VALUES (?)`, [`User ${name} submitted a new complaint (#${cId})`]);
        });
        res.json({ success: true, message: 'Complaint submitted successfully', complaintId: cId });
    });
});

// 6. Fetch User Complaints
app.get('/api/my-complaints', (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).json({ success: false, message: 'User ID is required.' });

    db.all(`SELECT * FROM Complaints WHERE user_id = ? AND is_deleted = 0 ORDER BY created_at DESC`, [userId], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Error fetching complaints.' });
        res.json({ success: true, complaints: rows });
    });
});

// 7. Update Location (Real-time tracking)
app.put('/api/update-location', (req, res) => {
    const { complaint_id, latitude, longitude } = req.body;
    db.run(`INSERT INTO Tracking (complaint_id, latitude, longitude) VALUES (?, ?, ?)`, [complaint_id, latitude, longitude], function (err) {
        if (err) return res.status(500).json({ success: false, message: 'Failed to save location.' });
        res.json({ success: true, message: 'Location updated.' });
    });
});

// 8. Delete Complaint (User)
app.delete('/api/complaints/:id', (req, res) => {
    const complaintId = req.params.id;
    const userId = req.headers['user-id']; // Expect user ID to be sent via header

    if (!userId) return res.status(400).json({ success: false, message: 'User ID required.' });

    db.get('SELECT * FROM Complaints WHERE id = ?', [complaintId], (err, row) => {
        if (err || !row) return res.status(404).json({ success: false, message: 'Complaint not found.' });
        if (row.user_id != userId) return res.status(403).json({ success: false, message: 'Unauthorized action.' });
        if (row.status !== 'Pending') {
            return res.status(400).json({ success: false, message: 'This complaint cannot be deleted as it is already being processed.' });
        }

        db.run('UPDATE Complaints SET is_deleted = 1 WHERE id = ?', [complaintId], function (err) {
            if (err) return res.status(500).json({ success: false, message: 'Failed to delete complaint.' });
            db.run('DELETE FROM Tracking WHERE complaint_id = ?', [complaintId]);
            db.run(`INSERT INTO ActivityLog (action) VALUES (?)`, [`User ID ${userId} deleted complaint #${complaintId}`]);
            res.json({ success: true, message: 'Your complaint has been successfully deleted.' });
        });
    });
});

// ======================= Admin APIs =======================

// 1. Admin Login
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Admin WHERE username = ?`, [username], async (err, row) => {
        if (err || !row) return res.status(401).json({ success: false, message: 'Invalid admin credentials' });

        const valid = await bcrypt.compare(password, row.password);
        if (!valid) return res.status(401).json({ success: false, message: 'Invalid admin credentials' });

        res.json({ success: true, message: 'Admin login successful' });
    });
});

// 2. Fetch all complaints
app.get('/api/admin/complaints', (req, res) => {
    db.all(`SELECT Complaints.*, Users.name as user_name, Users.email as user_email 
            FROM Complaints 
            LEFT JOIN Users ON Complaints.user_id = Users.id 
            WHERE Complaints.is_deleted = 0
            ORDER BY Complaints.created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Error fetching complaints.' });
        res.json({ success: true, complaints: rows });
    });
});

// 3. Update complaint status
app.put('/api/admin/complaints/:id/status', (req, res) => {
    const complaintId = req.params.id;
    const { status } = req.body;
    db.run(`UPDATE Complaints SET status = ? WHERE id = ?`, [status, complaintId], function (err) {
        if (err) return res.status(500).json({ success: false, message: 'Failed to update status.' });
        db.run(`INSERT INTO ActivityLog (action) VALUES (?)`, [`Complaint #${complaintId} status changed to ${status}`]);
        res.json({ success: true, message: 'Status updated successfully.' });
    });
});

// 4. Fetch Tracking History
app.get('/api/admin/complaints/:id/tracking', (req, res) => {
    const complaintId = req.params.id;
    db.all(`SELECT * FROM Tracking WHERE complaint_id = ? ORDER BY timestamp DESC`, [complaintId], (err, rows) => {
        if (err) return res.status(500).json({ success: false, message: 'Error fetching tracking data' });
        res.json({ success: true, tracking: rows });
    });
});

// 5. Delete Complaint (Admin)
app.delete('/api/admin/complaints/:id', (req, res) => {
    const complaintId = req.params.id;
    db.run('UPDATE Complaints SET is_deleted = 1 WHERE id = ?', [complaintId], function (err) {
        if (err) return res.status(500).json({ success: false, message: 'Failed to delete complaint.' });
        db.run('DELETE FROM Tracking WHERE complaint_id = ?', [complaintId]);
        db.run(`INSERT INTO ActivityLog (action) VALUES (?)`, [`Admin deleted complaint #${complaintId}`]);
        res.json({ success: true, message: 'Complaint deleted.' });
    });
});

// 6. Analytics Overview
app.get('/api/admin/analytics', (req, res) => {
    const runQuery = (q, params = []) => new Promise((resolve, reject) => db.all(q, params, (e, r) => e ? reject(e) : resolve(r)));
    const runSingle = (q, params = []) => new Promise((resolve, reject) => db.get(q, params, (e, r) => e ? reject(e) : resolve(r)));

    Promise.all([
        runSingle(`SELECT COUNT(*) as total FROM Complaints`),
        runSingle(`SELECT COUNT(*) as users FROM Users`),
        runSingle(`SELECT COUNT(*) as pending FROM Complaints WHERE status = 'Pending' AND is_deleted = 0`),
        runSingle(`SELECT COUNT(*) as in_progress FROM Complaints WHERE status = 'In Progress' AND is_deleted = 0`),
        runSingle(`SELECT COUNT(*) as resolved FROM Complaints WHERE status = 'Resolved' AND is_deleted = 0`),
        runSingle(`SELECT COUNT(*) as deleted FROM Complaints WHERE is_deleted = 1`),
        runQuery(`SELECT category, COUNT(*) as count FROM Complaints WHERE is_deleted = 0 GROUP BY category`),
        runQuery(`SELECT date(created_at) as date, COUNT(*) as count FROM Complaints WHERE is_deleted = 0 GROUP BY date(created_at) ORDER BY date DESC LIMIT 30`),
        runQuery(`SELECT date(created_at) as date, COUNT(*) as count FROM Users GROUP BY date(created_at) ORDER BY date DESC LIMIT 30`),
        runQuery(`SELECT Users.name as username, COUNT(Complaints.id) as total_complaints, MAX(Complaints.created_at) as last_activity 
                  FROM Users JOIN Complaints ON Users.id = Complaints.user_id 
                  GROUP BY Users.id ORDER BY total_complaints DESC LIMIT 5`),
        runQuery(`SELECT * FROM ActivityLog ORDER BY timestamp DESC LIMIT 10`)
    ]).then(results => {
        res.json({
            success: true,
            stats: {
                totalComplaints: results[0].total,
                totalUsers: results[1].users,
                pending: results[2].pending,
                inProgress: results[3].in_progress,
                resolved: results[4].resolved,
                deleted: results[5].deleted
            },
            categories: results[6],
            complaintsOverTime: results[7].reverse(),
            userGrowth: results[8].reverse(),
            topUsers: results[9],
            activityFeed: results[10]
        });
    }).catch(err => {
        res.status(500).json({ success: false, message: 'Analytics query error' });
    });
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
