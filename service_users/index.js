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

// Заглушка для маршрута
app.get('/', (req, res) => {
  res.send('Users Service is running');
});

// TODO: Реализовать остальные маршруты
app.post('/v1/register', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Registration not implemented yet' } });
});

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
