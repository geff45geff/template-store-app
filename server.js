// server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('./database');
const session = require('express-session');
const bcrypt = require('bcryptjs'); // Import bcryptjs
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

// Ensure uploads directory exists
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR);
}

// Set up Multer for file uploads
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, UPLOADS_DIR);
    },
    filename: function(req, file, cb) {
        const ext = path.extname(file.originalname);
        cb(null, req.body.slug + ext);
    }
});
const upload = multer({ storage: storage });

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-default-secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Authentication Middleware for Admin
const requireAdminLogin = (req, res, next) => {
    if (req.session && req.session.user && req.session.user.isAdmin) { // Check for isAdmin flag
        next();
    } else {
        res.redirect('/login'); // Redirect to admin login
    }
};

// Authentication Middleware for Regular Users
const requireUserLogin = (req, res, next) => {
    if (req.session && req.session.user && !req.session.user.isAdmin) { // Check for user and not admin
        next();
    } else {
        res.redirect('/user-login'); // Redirect to user login
    }
};

// Helper function to fetch products from the database
const getProductsFromDB = () => {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM products', [], (err, rows) => {
            if (err) {
                console.error('Error fetching products:', err.message);
                reject(new Error('Database error: Could not retrieve products.'));
            } else {
                resolve(rows);
            }
        });
    });
};

// Admin Authentication Routes
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        req.session.user = { username: username, isAdmin: true }; // Set isAdmin flag
        res.json({ success: true, message: 'Logged in successfully!' });
    } else {
        res.status(401).json({ error: 'Invalid username or password. Please try again.' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Failed to log out.' });
        }
        res.redirect('/login');
    });
});

// Apply admin authentication middleware to admin routes
app.use('/admin', requireAdminLogin);
app.use('/upload', requireAdminLogin);
app.use('/product', requireAdminLogin);

// User Registration Routes
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // Check if user already exists
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(new Error('Database error during user lookup.'));
                else resolve(row);
            });
        });

        if (existingUser) {
            return res.status(409).json({ error: 'User with this email already exists.' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Insert new user into database
        await new Promise((resolve, reject) => {
            db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
                if (err) reject(new Error('Failed to register user in database.'));
                else resolve(this.lastID);
            });
        });

        res.status(201).json({ message: 'Registration successful! Please log in.' });
    } catch (error) {
        console.error('Error during user registration:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// User Login Routes
app.get('/user-login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user-login.html'));
});

app.post('/user-login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        const user = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(new Error('Database error during user login.'));
                else resolve(row);
            });
        });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            req.session.user = { id: user.id, email: user.email, isAdmin: false }; // Set user session
            res.json({ success: true, message: 'Login successful!' });
        } else {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error('Error during user login:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// User Logout
app.get('/user-logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying user session:', err);
            return res.status(500).json({ error: 'Failed to log out.' });
        }
        // Send a JSON response for the frontend to handle
        res.json({ success: true, message: 'Logged out successfully!' });
    });
});

// New API endpoint to check user login status
app.get('/api/user-status', (req, res) => {
    if (req.session && req.session.user && !req.session.user.isAdmin) {
        res.json({ loggedIn: true, email: req.session.user.email });
    } else {
        res.json({ loggedIn: false });
    }
});


// Serve the products data from the database (for frontend display)
app.get('/products', async (req, res) => {
    try {
        const products = await getProductsFromDB();
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Serve the success.html page
app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

// Admin Panel route - now protected
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Upload route - now protected
app.post('/upload', upload.single('templateFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded. Please select a file.' });
    }

    const { name, price, slug } = req.body;
    if (!name || !price || !slug) {
        fs.unlinkSync(req.file.path); // Delete partially uploaded file
        return res.status(400).json({ error: 'Missing product details: name, price, or slug. All fields are required.' });
    }

    // Basic validation for price
    if (isNaN(parseFloat(price)) || !isFinite(price) || parseFloat(price) <= 0) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Invalid price. Please enter a positive number.' });
    }

    try {
        const existingProduct = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM products WHERE slug = ?', [slug], (err, row) => {
                if (err) reject(new Error('Database error during slug check.'));
                else resolve(row);
            });
        });

        if (existingProduct) {
            fs.unlinkSync(req.file.path);
            return res.status(409).json({ error: `Product with slug '${slug}' already exists. Please use a unique slug.` });
        }

        const filePath = path.basename(req.file.path);
        await new Promise((resolve, reject) => {
            db.run('INSERT INTO products (name, price, slug, file_path) VALUES (?, ?, ?, ?)', [name, price, slug, filePath], function(err) {
                if (err) {
                    fs.unlinkSync(req.file.path);
                    reject(new Error('Failed to save product to database.'));
                } else {
                    resolve(this.lastID);
                }
            });
        });

        res.json({ message: 'Template uploaded and product added successfully!' });
    } catch (error) {
        console.error('Error adding product to database:', error.message);
        res.status(500).json({ error: error.message });
    }
});


// Route to get a single product by ID (for edit modal) - protected
app.get('/product/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const product = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM products WHERE id = ?', [id], (err, row) => {
                if (err) reject(new Error('Database error: Could not retrieve product.'));
                else if (!row) reject(new Error('Product not found.'));
                else resolve(row);
            });
        });
        res.json(product);
    } catch (error) {
        console.error(`Error fetching product ${id}:`, error.message);
        res.status(404).json({ error: error.message });
    }
});


// Route to update a product - protected
app.put('/product/:id', async (req, res) => {
    const { id } = req.params;
    const { name, price, slug } = req.body;

    if (!name || !price || !slug) {
        return res.status(400).json({ error: 'Missing product details: name, price, or slug. All fields are required.' });
    }

    if (isNaN(parseFloat(price)) || !isFinite(price) || parseFloat(price) <= 0) {
        return res.status(400).json({ error: 'Invalid price. Please enter a positive number.' });
    }

    try {
        const existingProductWithSlug = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM products WHERE slug = ? AND id != ?', [slug, id], (err, row) => {
                if (err) reject(new Error('Database error during slug uniqueness check.'));
                else resolve(row);
            });
        });

        if (existingProductWithSlug) {
            return res.status(409).json({ error: `Product with slug '${slug}' already exists for another product. Please choose a unique slug.` });
        }

        await new Promise((resolve, reject) => {
            db.run('UPDATE products SET name = ?, price = ?, slug = ? WHERE id = ?', [name, price, slug, id], function(err) {
                if (err) reject(new Error('Failed to update product in database.'));
                else if (this.changes === 0) reject(new Error('Product not found or no changes were made.'));
                else resolve();
            });
        });
        res.json({ message: 'Product updated successfully!' });
    } catch (error) {
        console.error(`Error updating product ${id}:`, error.message);
        res.status(500).json({ error: error.message });
    }
});


// Route to delete a product - protected
app.delete('/product/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const productToDelete = await new Promise((resolve, reject) => {
            db.get('SELECT file_path FROM products WHERE id = ?', [id], (err, row) => {
                if (err) reject(new Error('Database error during product lookup for deletion.'));
                else if (!row) reject(new Error('Product not found.'));
                else resolve(row);
            });
        });

        await new Promise((resolve, reject) => {
            db.run('DELETE FROM products WHERE id = ?', [id], function(err) {
                if (err) reject(new Error('Failed to delete product from database.'));
                else if (this.changes === 0) reject(new Error('Product not found.'));
                else resolve();
            });
        });

        const filePath = path.join(UPLOADS_DIR, productToDelete.file_path);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            console.log(`Deleted file: ${filePath}`);
        } else {
            console.warn(`File not found for deletion (already missing?): ${filePath}`);
        }

        res.json({ message: 'Product deleted successfully!' });
    } catch (error) {
        console.error(`Error deleting product ${id}:`, error.message);
        res.status(500).json({ error: error.message });
    }
});


// Route to create a new Coinbase Commerce charge
app.post('/create-charge', async (req, res) => {
    const { product_id } = req.body;

    try {
        const product = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM products WHERE id = ?', [product_id], (err, row) => {
                if (err) reject(new Error('Database error: Could not retrieve product for charge.'));
                else resolve(row);
            });
        });

        if (!product) {
            return res.status(404).json({ error: 'Product not found. Please try again or contact support.' });
        }

        const response = await axios.post(
            'https://api.commerce.coinbase.com/charges', {
                name: product.name,
                description: `Purchase of ${product.name}`,
                local_price: {
                    amount: product.price,
                    currency: 'USD',
                },
                pricing_type: 'fixed_price',
                metadata: {
                    product_id: product.id,
                    product_slug: product.slug,
                },
                redirect_url: `${process.env.BASE_URL || `http://localhost:${port}`}/success?charge_id={{charge_id}}&slug=${product.slug}`,
                cancel_url: `${process.env.BASE_URL || `http://localhost:${port}`}/cancel`,
            }, {
                headers: {
                    'X-CC-Api-Key': process.env.COINBASE_COMMERCE_API_KEY,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
            }
        );
        res.json(response.data.data);
    } catch (error) {
        console.error('Error creating charge:', error.response ? error.response.data : error.message);
        const errorMessage = error.response && error.response.data && error.response.data.error ?
            `Coinbase Commerce Error: ${error.response.data.error.message}` :
            'Failed to initiate payment. Please try again.';
        res.status(500).json({ error: errorMessage, details: error.response ? error.response.data : error.message });
    }
});

// Coinbase Commerce Webhook Endpoint
app.post('/coinbase-webhook', async (req, res) => {
    const WEBHOOK_SECRET = process.env.COINBASE_COMMERCE_WEBHOOK_SECRET;
    const signature = req.headers['x-cc-webhook-signature'];
    const payload = JSON.stringify(req.body);

    if (!signature) {
        console.error('Webhook received without signature header');
        return res.status(400).send('No signature');
    }

    try {
        const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
        hmac.update(payload);
        const digest = hmac.digest('hex');

        if (digest !== signature) {
            console.error('Webhook signature mismatch!');
            return res.status(400).send('Invalid signature');
        }

        const event = req.body;

        switch (event.event.type) {
            case 'charge:confirmed':
                const chargeData = event.event.data;
                const productId = chargeData.metadata.product_id;
                const productSlug = chargeData.metadata.product_slug;
                const chargeCode = chargeData.code;

                try {
                    await new Promise((resolve, reject) => {
                        db.run('INSERT OR IGNORE INTO transactions (charge_code, product_id, product_slug, status, charge_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)', [chargeCode, productId, productSlug, 'paid', chargeData.id, chargeData.expires_at], (err) => {
                            if (err) reject(new Error('Failed to record transaction in database.'));
                            else resolve();
                        });
                    });
                    console.log(`Transaction ${chargeCode} for product ${productId} marked as paid in the database.`);
                } catch (dbError) {
                    console.error('Error inserting transaction into database:', dbError.message);
                    return res.status(500).send('Error updating transaction status');
                }
                break;
            case 'charge:pending':
                console.log('Charge Pending:', event.event.data.code);
                break;
            case 'charge:failed':
                console.log('Charge Failed:', event.event.data.code);
                break;
            case 'charge:resolved':
                console.log('Charge Resolved:', event.event.data.code);
                break;
            default:
                console.log(`Unhandled event type: ${event.event.type}`);
        }

        res.status(200).send('Webhook received and processed');

    } catch (error) {
        console.error('Error processing webhook:', error.message);
        res.status(500).send('Internal server error during webhook processing.');
    }
});

// Secure Download Route
app.get('/download/:charge_code/:slug', async (req, res) => {
    const { charge_code, slug } = req.params;

    try {
        const transaction = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM transactions WHERE charge_code = ?', [charge_code], (err, row) => {
                if (err) reject(new Error('Database error during transaction lookup for download.'));
                else resolve(row);
            });
        });

        if (!transaction) {
            console.warn(`Download attempt with unknown charge_code: ${charge_code}`);
            return res.status(403).send('Access Denied. Invalid or expired download link.');
        }

        if (transaction.product_slug !== slug || transaction.status !== 'paid') {
            console.warn(`Download attempt failed for charge_code: ${charge_code}. Mismatch or not paid. Slug: ${slug}, Expected: ${transaction.product_slug}, Status: ${transaction.status}`);
            return res.status(403).send('Access Denied or Payment Not Confirmed.');
        }

        const product = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM products WHERE slug = ?', [slug], (err, row) => {
                if (err) reject(new Error('Database error: Could not retrieve product details for download.'));
                else resolve(row);
            });
        });

        if (!product || !product.file_path) {
            console.error(`Product or file path not found for slug: ${slug}`);
            return res.status(404).send('Product file not found on server or its path is missing.');
        }

        const filePath = path.join(UPLOADS_DIR, product.file_path);

        if (fs.existsSync(filePath)) {
            res.download(filePath, product.name + path.extname(product.file_path), (err) => {
                if (err) {
                    console.error(`Error sending file ${filePath}:`, err);
                    if (!res.headersSent) { // Prevent setting headers twice
                        res.status(500).send('Error downloading file. Please try again.');
                    }
                } else {
                    console.log(`Successfully downloaded ${filePath}`);
                }
            });
        } else {
            console.error(`File not found at: ${filePath}`);
            res.status(404).send('The requested file is not available on the server. Please contact support.');
        }
    } catch (error) {
        console.error('Server error during download:', error.message);
        res.status(500).send('An unexpected error occurred during download. Please try again.');
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
    console.log(`Access the store at: http://localhost:${port}`);
    console.log(`Access the admin panel at: http://localhost:${port}/admin`);
    console.log(`Register a new user at: http://localhost:${port}/register`);
});