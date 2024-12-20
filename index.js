const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const ejs = require('ejs');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Initialize the database
app.get('/', (req, res) => {
  res.send('Welcome to the Password Manager');
});
let db = new sqlite3.Database(':memory:');
const session = require('express-session');
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// Middleware to check if user is logged in
function isLoggedIn(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login');
}

app.get('/', isLoggedIn, (req, res) => {
  db.all("SELECT * FROM vaults WHERE user_id = ?", [req.session.user.id], (err, rows) => {
    if (err) return res.status(500).send('Error retrieving passwords');
    res.render('index', { username: req.session.user.username, passwords: rows });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Error logging out');
    res.redirect('/login');
  });
});

app.get('/add-password', isLoggedIn, (req, res) => {
  res.render('add-password');
});

app.post('/add-password', isLoggedIn, (req, res) => {
  const { username, password, website, notes } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).send('Error hashing password');
    db.run("INSERT INTO vaults (user_id, key, value, notes) VALUES (?, ?, ?, ?)", [req.session.user.id, username, hash, website, notes], function(err) {
      if (err) return res.status(500).send('Error adding password');
      res.redirect('/');
    });
  });
});

db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
  db.run("CREATE TABLE vaults (user_id INTEGER, key TEXT, value TEXT)");
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).send('Error hashing password');
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function(err) {
      if (err) return res.status(409).send('Username already exists');
      res.send(`User ${username} registered successfully`);
    });
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) return res.status(500).send('Error retrieving user');
    if (!user) return res.status(401).send('User not found');
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).send('Error comparing passwords');
      if (result) res.send(`Welcome ${username}`);
      else res.status(401).send('Incorrect password');
    });
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});