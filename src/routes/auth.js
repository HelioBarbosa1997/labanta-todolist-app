
const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');

const router = express.Router();

// GET /register
router.get('/register', (req, res) => {
  res.render('register', {
    error: null,
    username: null
  });
});

// POST /register
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Validar dados
    if (!username || !password) {
      return res.render('register', {
        error: 'Username e password são obrigatórios.',
        username
      });
    }

    // Verificar se o utilizador já existe
    const verificar = await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    );

    if (verificar.rows.length > 0) {
      return res.render('register', {
        error: 'Utilizador já existe.',
        username
      });
    }

    // Criar hash da password
    const passwordHash = await bcrypt.hash(password, 12);

    // Query parametrizada
    await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2)',
      [username, passwordHash]
    );

    res.redirect('/login');

  } catch (error) {

        console.error('Erro no POST /register:', error);
    res.status(500).render('register', {
      error: 'Erro interno do servidor.',
      username
    });
  }
});

// GET /login
router.get('/login', (req, res) => {
  res.render('login', {
    error: null,
    username: null
  });
});

// POST /login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Query parametrizada fora do base de dados para evitar SQL
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    const user = result.rows[0];

    if (!user) {
      return res.render('login', {
        error: 'Credenciais inválidas.',
        username
      });
    }

    // Comparar password enviada com o hash
    const passwordValida = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordValida) {
      return res.render('login', {
        error: 'Credenciais inválidas.',
        username
      });
    }

    // Regenerar a sessão depois do login
    req.session.regenerate((err) => {
      if (err) {

        return res.status(500).render('login', {
          error: 'Erro ao iniciar sessão.',
          username
        });
      }

      req.session.userId = user.id;
      req.session.username = user.username;

      res.redirect('/tasks');
    });

  } catch (error) {


    res.status(500).send('Erro interno do servidor.');
  }
});

// POST /logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {

      return res.status(500).send('Erro ao terminar sessão.');
    }

    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = router;