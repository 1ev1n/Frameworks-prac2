const express = require('express');
const cors = require('cors');
const pino = require('pino');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./src/db'); // Подключаем наш модуль для работы с БД

const app = express();
const PORT = process.env.PORT || 3001; // Изменен порт для сервиса пользователей
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey';

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Middleware для добавления Request ID и логирования
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || uuidv4();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  logger.info({ requestId, method: req.method, url: req.url }, 'Incoming request');
  next();
});

// CORS и JSON парсер
app.use(cors());
app.use(express.json());

// Схема валидации для регистрации
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  name: Joi.string().required(),
  roles: Joi.array().items(Joi.string().valid('user', 'admin')).default(['user']),
});

// Запуск миграций при старте сервиса
async function runMigrations() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        roles TEXT[] DEFAULT '{user}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    logger.info('Миграции для таблицы users успешно выполнены.');
  } catch (error) {
    logger.error({ error: error.message }, 'Ошибка при выполнении миграций для таблицы users.');
    process.exit(1); // Завершаем работу сервиса при ошибке миграции
  }
}

// Маршрут регистрации
app.post('/v1/register', async (req, res) => {
  const requestId = req.requestId;
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      logger.error({ requestId, error: error.details[0].message }, 'Validation error');
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });
    }

    const { email, password, name, roles } = value;

    const existingUser = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      logger.warn({ requestId, email }, 'User already exists');
      return res.status(409).json({ success: false, error: { code: 'USER_EXISTS', message: 'User with this email already exists' } });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const createdAt = new Date();
    const updatedAt = new Date();

    const newUser = await db.query(
      'INSERT INTO users (id, email, password_hash, name, roles, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, name, roles, created_at, updated_at',
      [id, email, passwordHash, name, roles, createdAt, updatedAt]
    );

    logger.info({ requestId, userId: newUser.rows[0].id }, 'User registered successfully');
    res.status(201).json({ success: true, data: { id: newUser.rows[0].id, email: newUser.rows[0].email, name: newUser.rows[0].name, roles: newUser.rows[0].roles, createdAt: newUser.rows[0].created_at, updatedAt: newUser.rows[0].updated_at } });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error during user registration');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// TODO: Реализовать остальные маршруты
app.post('/v1/login', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Login not implemented yet' } });
});

app.get('/v1/profile', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Profile retrieval not implemented yet' } });
});

app.put('/v1/profile', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Profile update not implemented yet' } });
});

app.get('/v1/users', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'User list retrieval not implemented yet' } });
});


// Запуск сервера и миграций
app.listen(PORT, '0.0.0.0', async () => {
  logger.info(`Users Service запущен на порту ${PORT}`);
  await runMigrations();
});
