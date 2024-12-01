const express = require('express');
const https = require('https');
const fs = require('fs');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors'); 
require('dotenv').config();

const app = express();

// Настройка CORS
app.use(cors());

// Настройка HTTPS-сертификатов
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/api.dvoich.ru/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/api.dvoich.ru/fullchain.pem'),
};

// Настройка подключения к PostgreSQL
const pool = new Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

// Middleware для парсинга JSON
app.use(express.json());

// Регистрация нового пользователя
app.post('/register', async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ message: 'Логин и пароль обязательны.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (login, password) VALUES ($1, $2) RETURNING id, login',
      [login, hashedPassword]
    );

    const user = result.rows[0];
    res.status(201).json({ message: 'Пользователь зарегистрирован', user });
  } catch (err) {
    console.error('Ошибка регистрации:', err);
    res.status(500).json({ message: 'Ошибка регистрации пользователя' });
  }
});

// Вход пользователя (авторизация)
app.post('/login', async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({ message: 'Логин и пароль обязательны.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Неверный логин или пароль.' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Неверный логин или пароль.' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Успешный вход', token });
  } catch (err) {
    console.error('Ошибка входа:', err);
    res.status(500).json({ message: 'Ошибка авторизации' });
  }
});

// Пример защищённого маршрута
app.get('/protected', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ message: 'Токен не предоставлен' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Неверный токен' });
    }

    res.status(200).json({ message: 'Доступ разрешён', userId: decoded.userId });
  });
});

// Маршрут проверки
app.get('/test', async (req, res) => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    client.release();
    res.status(200).send(`Сервер работает. Текущее время: ${result.rows[0].now}`);
  } catch (err) {
    console.error('Ошибка подключения к БД:', err);
    res.status(500).send('Ошибка подключения к базе данных');
  }
});

// Запуск сервера
const PORT = 443;
https.createServer(options, app).listen(PORT, 'api.dvoich.ru', () => {
  console.log(`Сервер работает на https://api.dvoich.ru:${PORT}`);
});
