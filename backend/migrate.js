const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'complaints.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    db.all(`SELECT * FROM Users`, async (err, rows) => {
        if (err) return console.error(err);
        let updated = 0;
        for (const user of rows) {
            // Check if password is not already a bcrypt hash (bcrypt hashes usually start with $2a$, $2b$, $2y$)
            if (user.password && !user.password.startsWith('$2')) {
                const hash = await bcrypt.hash(user.password, 10);
                db.run(`UPDATE Users SET password = ? WHERE id = ?`, [hash, user.id], (err) => {
                    if (err) console.error("Failed to update user", user.id);
                    else {
                        updated++;
                        console.log("Migrated password for user:", user.email);
                    }
                });
            }
        }
    });
});
