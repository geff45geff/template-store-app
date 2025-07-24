// database.js

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Using 'data' directory for the database file
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}
const DB_PATH = path.join(dataDir, 'data.db'); // Changed to store in 'data' directory

// Check if the database file exists, if not, create it and initialize schema
const dbExists = fs.existsSync(DB_PATH);

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');

        // Always run schema creation to ensure tables exist, using IF NOT EXISTS
        // This is more robust than only running if !dbExists, especially during development
        db.serialize(() => {
            // Create products table - ADDED description and stock
            db.run(`CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,           -- ADDED
                price REAL NOT NULL,
                stock INTEGER DEFAULT 0,    -- ADDED with default
                slug TEXT UNIQUE NOT NULL,
                file_path TEXT NOT NULL
            )`, (err) => {
                if (err) {
                    console.error('Error creating products table:', err.message);
                } else {
                    console.log('Products table ensured.');
                }
            });

            // Create transactions table
            db.run(`CREATE TABLE IF NOT EXISTS transactions (
                charge_code TEXT PRIMARY KEY,
                product_id INTEGER NOT NULL,
                product_slug TEXT NOT NULL,
                status TEXT NOT NULL,
                charge_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (product_id) REFERENCES products(id)
            )`, (err) => {
                if (err) {
                    console.error('Error creating transactions table:', err.message);
                } else {
                    console.log('Transactions table ensured.');
                }
            });

            // Create users table - ADDED is_admin column
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, -- Hashed password
                is_admin INTEGER DEFAULT 0, -- ADDED: 0 for regular user, 1 for admin
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => {
                if (err) {
                    console.error('Error creating users table:', err.message);
                } else {
                    console.log('Users table ensured.');
                }
            });
        });
    }
});

module.exports = db;