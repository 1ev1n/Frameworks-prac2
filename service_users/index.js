const express = require('express');
const cors = require('cors');
const pino = require('pino');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./src/db'); // Подключаем наш модуль для работы с БД
const { authenticateJWT, authorizeRoles } = require('./middleware/auth'); // Подключаем middleware для аутентификации и авторизации

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

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const profileUpdateSchema = Joi.object({
  name: Joi.string().optional(),
  roles: Joi.array().items(Joi.string().valid('user', 'admin')).optional(),
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

// Маршрут входа
app.post('/v1/login', async (req, res) => {
  const requestId = req.requestId;
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      logger.error({ requestId, error: error.details[0].message }, 'Validation error');
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });
    }

    const { email, password } = value;

    const user = await db.query('SELECT id, email, password_hash, name, roles FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      logger.warn({ requestId, email }, 'Authentication failed: User not found');
      return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } });
    }

    const storedUser = user.rows[0];
    const passwordMatch = await bcrypt.compare(password, storedUser.password_hash);

    if (!passwordMatch) {
      logger.warn({ requestId, email }, 'Authentication failed: Incorrect password');
      return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } });
    }

    const token = jwt.sign(
      { id: storedUser.id, email: storedUser.email, roles: storedUser.roles },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    logger.info({ requestId, userId: storedUser.id }, 'User logged in successfully');
    res.status(200).json({ success: true, data: { token } });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error during user login');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Маршрут получения профиля
app.get('/v1/profile', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    // req.user устанавливается middleware authenticateJWT
    const userId = req.user.id;

    const user = await db.query('SELECT id, email, name, roles, created_at, updated_at FROM users WHERE id = $1', [userId]);

    if (user.rows.length === 0) {
      logger.warn({ requestId, userId }, 'Profile not found for authenticated user');
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'User profile not found' } });
    }

    logger.info({ requestId, userId }, 'User profile retrieved successfully');
    res.status(200).json({ success: true, data: user.rows[0] });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error retrieving user profile');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Маршрут обновления профиля
app.put('/v1/profile', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    const { error, value } = profileUpdateSchema.validate(req.body);
    if (error) {
      logger.error({ requestId, error: error.details[0].message }, 'Validation error for profile update');
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });
    }

    const userId = req.user.id;
    const { name, roles } = value;

    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;

    if (name !== undefined) {
      updateFields.push(`name = $${paramIndex++}`);
      updateValues.push(name);
    }
    if (roles !== undefined) {
      // Только админ может менять роли другого пользователя, или пользователь может менять свои роли (если не является админом)
      if (req.user.roles.includes('admin')) {
        updateFields.push(`roles = $${paramIndex++}`);
        updateValues.push(roles);
      } else if (roles.some(role => !req.user.roles.includes(role))) {
        // Если пользователь не админ и пытается добавить роль, которую у него нет, или удалить свою единственную роль
        logger.warn({ requestId, userId, attemptedRoles: roles }, 'User tried to change roles without admin privileges');
        return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions to change roles' } });
      }
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ success: false, error: { code: 'NO_CHANGES', message: 'No fields to update' } });
    }

    updateValues.push(new Date()); // updated_at
    updateFields.push(`updated_at = $${paramIndex++}`);
    updateValues.push(userId);

    const updatedUser = await db.query(
      `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramIndex} RETURNING id, email, name, roles, created_at, updated_at`,
      updateValues
    );

    if (updatedUser.rows.length === 0) {
      logger.warn({ requestId, userId }, 'User for profile update not found');
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'User not found' } });
    }

    logger.info({ requestId, userId }, 'User profile updated successfully');
    res.status(200).json({ success: true, data: updatedUser.rows[0] });

  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error updating user profile');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Маршрут получения списка пользователей (только для админов)
app.get('/v1/users', authenticateJWT, authorizeRoles(['admin']), async (req, res) => {
  const requestId = req.requestId;
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const users = await db.query(
      'SELECT id, email, name, roles, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2',
      [limit, offset]
    );

    const totalUsers = await db.query('SELECT COUNT(*) FROM users');
    const total = parseInt(totalUsers.rows[0].count);

    logger.info({ requestId, page, limit, total }, 'Users list retrieved successfully');
    res.status(200).json({ success: true, data: users.rows, pagination: { total, page, limit } });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error retrieving users list');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Запуск сервера и миграций
app.listen(PORT, '0.0.0.0', async () => {
  logger.info(`Users Service запущен на порту ${PORT}`);
  await runMigrations();
});
