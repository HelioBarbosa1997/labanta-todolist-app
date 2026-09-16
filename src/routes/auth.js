const express = require('express');
const pool = require('../db');
const router = express.Router();
const bcrypt = require('bcrypt');

// GET /register - Render the registration page
router.get('/register', (req, res) => res.render('register', { error: null, username: null }));

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    // VULNERÁVEL: password guardada em texto simples + query por concatenação (SQL Injection)
    const query = `INSERT INTO users (username, password_hash) VALUES ($1, $2)`;
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(query, [username, hashedPassword]);
    res.redirect('/login');

  

  } catch (err) {
    res.render('register', { error: 'Utilizador já existe ou dados inválidos.', username: null });
  }
});

router.get('/login', (req, res) => res.render('login', { error: null, username: null }));

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERÁVEL: query por concatenação de string + comparação direta de password em texto simples
  const query = `SELECT * FROM users WHERE username = $1`;
  console.log({ query });
  const result = await pool.query(query, [username]);
  const user = result.rows[0];

  let match = false;
  if (user) {
    match = await bcrypt.compare(password, user.password_hash);
  }

  if (!match) {
    return res.render('login', { error: 'Credenciais inválidas.', username: null });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.redirect(`/tasks`);
});

// GET /logout - Handle user logout
router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

module.exports = router;



