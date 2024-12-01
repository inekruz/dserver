const express = require('express');
const https = require('https');
const fs = require('fs');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();


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