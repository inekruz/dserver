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

// Получение user_id по логину
app.post('/get-user-id', async (req, res) => {
  const { login } = req.body;

  if (!login) {
    return res.status(400).json({ message: 'Логин обязателен.' });
  }

  try {
    const result = await pool.query('SELECT id FROM users WHERE login = $1', [login]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден.' });
    }

    const user = result.rows[0];
    res.status(200).json({ user_id: user.id });
  } catch (err) {
    console.error('Ошибка при получении user_id:', err);
    res.status(500).json({ message: 'Ошибка сервера' });
  }
});

// Получение категорий для пользователя
app.get('/categories', async (req, res) => {
  const { user_id } = req.query;

  if (!user_id) {
      return res.status(400).json({ message: 'Не указан user_id.' });
  }

  try {
      const result = await pool.query(
          'SELECT id, name FROM categories WHERE user_id = $1',
          [user_id]
      );
      res.status(200).json(result.rows);
  } catch (err) {
      console.error('Ошибка получения категорий:', err);
      res.status(500).json({ message: 'Ошибка при получении категорий.' });
  }
});

app.post('/getTransactions', async (req, res) => {
  const { user_id, category, srok } = req.body;

  if (!user_id || !category || !srok) {
    return res.status(400).json({ message: 'user_id, category и srok обязательны.' });
  }

  try {
    const currentDate = new Date();
    let query = `SELECT user_id, category_id, amount, date, description, created_at, updated_at
                 FROM transactions WHERE user_id = $1`;

    const params = [user_id];  // Массив параметров для запроса, в который будет добавляться user_id

    // Если категория не выбрана (например, 'всё'), то фильтрация по категории не будет добавляться
    if (category !== 'всё') {
      query += ` AND category_id = $2`;
      params.push(category);  // Добавляем category в параметры запроса
    }

    let dateFilter = '';
    if (srok === 'месяц') {
      dateFilter = ` AND date >= $${params.length + 1}::timestamp`;
      currentDate.setMonth(currentDate.getMonth() - 1);
      params.push(currentDate);  // Добавляем параметр даты
    } else if (srok === 'три месяца') {
      dateFilter = ` AND date >= $${params.length + 1}::timestamp`;
      currentDate.setMonth(currentDate.getMonth() - 3);
      params.push(currentDate);  // Добавляем параметр даты
    } else if (srok === 'год') {
      dateFilter = ` AND date >= $${params.length + 1}::timestamp`;
      currentDate.setFullYear(currentDate.getFullYear() - 1);
      params.push(currentDate);  // Добавляем параметр даты
    } else if (srok === 'всё время') {
      dateFilter = '';  // Нет фильтра по дате
    }

    query += dateFilter;
    query += ' ORDER BY category_id, date DESC';

    const result = await pool.query(query, params); // Передаем params в запрос

    let categoryName = null;
    if (category !== 'всё') {
      const categoryResult = await pool.query(
        'SELECT name FROM categories WHERE id = $1 AND user_id = $2',
        [category, user_id]
      );

      if (categoryResult.rows.length > 0) {
        categoryName = categoryResult.rows[0].name;
      }
    }

    const transactions = result.rows.map(transaction => ({
      ...transaction,
      category_name: categoryName || 'Всё',  // Если категория не найдена, используем 'Всё'
    }));

    res.status(200).json(transactions);

  } catch (err) {
    console.error('Ошибка запроса к базе данных:', err);
    res.status(500).json({ message: 'Ошибка запроса к базе данных' });
  }
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
