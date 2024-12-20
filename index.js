const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const ejs = require('ejs');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Initialize the database
let db = new sqlite3.Database(':memory:');

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