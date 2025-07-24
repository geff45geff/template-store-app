// database.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'data.db');

// Check if the database file exists, if not, create it and initialize schema
const dbExists = fs.existsSync(DB_PATH);

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        if (!dbExists) {
            db.serialize(() => {
                // Create products table
                db.run(`CREATE TABLE products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    price REAL NOT NULL,
                    slug TEXT UNIQUE NOT NULL,
                    file_path TEXT NOT NULL
                )`, (err) => {
                    if (err) {
                        console.error('Error creating products table:', err.message);
                    } else {
                        console.log('Products table created.');
                    }
                });

                // Create transactions table
                db.run(`CREATE TABLE transactions (
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
                        console.log('Transactions table created.');
                    }
                });

                // New: Create users table
                db.run(`CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL, -- Hashed password
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`, (err) => {
                    if (err) {
                        console.error('Error creating users table:', err.message);
                    } else {
                        console.log('Users table created.');
                    }
                });
            });
        }
    }
});

module.exports = db;