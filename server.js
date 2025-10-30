require('dotenv').config();

// 1. Import dependencies
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// 2. JWT secret
// Use the JWT_SECRET from our .env file
const JWT_SECRET = process.env.JWT_SECRET;

// 3. Create Express app
const app = express();
const port = process.env.PORT || 3000;

// 4. Middleware
app.use(cors());
app.use(express.json());

// This is our bouncer middleware
const authenticateToken = (req, res, next) => {
  // Get the token from the 'Authorization' header
  const authHeader = req.headers['authorization'];
  
  // *** THIS IS THE FIX ***
  // Split by the space ' ' not by an empty string ''
  const token = authHeader && authHeader.split(' ')[1]; // Format is "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // 401 = unauthorized
  }

  // Verify the token 
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // 403 = Forbidden (token is no longer valid)
    }

    // Token is valid! Attach the user's info to the request object
    req.user = user;
    next(); // Call 'next()' to pass control to the next function (our route)
  });
};

// 5. Database connection
const isProduction = process.env.NODE_ENV === 'production';
const connectionString = isProduction
  ? process.env.DATABASE_URL
  : `postgresql://postgres:${process.env.DATABASE_PASSWORD}@localhost:5432/quotes_db`;


const pool = new Pool({
  connectionString: connectionString, 
  ssl: isProduction ?
  { rejectUnauthorized: false } : false,
});

// --- AUTH ROUTES ---

// REGISTER
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
      [email, passwordHash]
    );

    res.json({ message: 'User created successfully', user: newUser.rows[0] });
  } catch (err) {
    console.error(err.message);
    if (err.code === '23505') {
      return res.status(400).send('Email already in use.');
    }
    res.status(500).send('Server error');
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const isValidPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!isValidPassword) {
      return res.status(401).send('Invalid credentials');
    }

    const token = jwt.sign(
      { userId: user.rows[0].id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Logged in successfully', token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// --- QUOTES ROUTES ---

// Get all quotes
app.get('/api/quotes', async (req, res) => {
  try {
    const allQuotes = await pool.query('SELECT * FROM quotes ORDER BY id ASC');
    res.json(allQuotes.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Get single quote by ID
app.get('/api/quotes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const quote = await pool.query('SELECT * FROM quotes WHERE id = $1', [id]);
    if (quote.rows.length === 0) {
      return res.status(404).send('Quote not found');
    }
    res.json(quote.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Create a new quote
// POST a new quote (create) - NOW SECURED!
app.post('/api/quotes', authenticateToken, async (req, res) => {
  try {
    // We can access req.user here!
    console.log(`Quote added by user ID: ${req.user.userId}`);
    
    const { author, quote } = req.body;
    const newQuote = await pool.query(
      'INSERT INTO quotes (author, quote) VALUES ($1, $2) RETURNING *',
      [author, quote]
    );
    res.json(newQuote.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// Start server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running at http://localhost:${port}`);
});
