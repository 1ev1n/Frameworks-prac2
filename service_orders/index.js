const express = require('express');
const cors = require('cors');
const pino = require('pino');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const db = require('./src/db'); // Подключаем наш модуль для работы с БД
const { authenticateJWT, authorizeRoles } = require('./middleware/auth'); // Подключаем middleware для аутентификации и авторизации

const app = express();
const PORT = process.env.PORT || 3002; // Изменен порт для сервиса заказов
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretjwtkey'; // Используется для JWT в middleware

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

// Схема валидации для создания заказа
const createOrderSchema = Joi.object({
  items: Joi.array().items(Joi.object({
    product: Joi.string().required(),
    quantity: Joi.number().integer().min(1).required(),
  })).min(1).required(),
  totalAmount: Joi.number().positive().required(),
});


// Запуск миграций при старте сервиса
async function runMigrations() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL,
        items JSONB NOT NULL,
        status VARCHAR(50) DEFAULT 'created',
        total_amount NUMERIC(10, 2) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);
    logger.info('Миграции для таблицы orders успешно выполнены.');
  } catch (error) {
    logger.error({ error: error.message }, 'Ошибка при выполнении миграций для таблицы orders.');
    process.exit(1); // Завершаем работу сервиса при ошибке миграции
  }
}

// Заглушка для маршрута
app.get('/', (req, res) => {
  res.send('Orders Service is running');
});

// Маршрут создания заказа
app.post('/v1/orders', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    const { error, value } = createOrderSchema.validate(req.body);
    if (error) {
      logger.error({ requestId, error: error.details[0].message }, 'Validation error for order creation');
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });
    }

    const { items, totalAmount } = value;
    const userId = req.headers['x-user-id']; // Получаем ID пользователя из заголовка от API Gateway

    if (!userId) {
      logger.warn({ requestId }, 'User ID not found in headers for order creation');
      return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'User ID not found' } });
    }

    const id = uuidv4();
    const createdAt = new Date();
    const updatedAt = new Date();

    const newOrder = await db.query(
      'INSERT INTO orders (id, user_id, items, total_amount, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, user_id, items, status, total_amount, created_at, updated_at',
      [id, userId, JSON.stringify(items), totalAmount, createdAt, updatedAt]
    );

    logger.info({ requestId, orderId: newOrder.rows[0].id, userId }, 'Order created successfully');
    res.status(201).json({ success: true, data: newOrder.rows[0] });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error creating order');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});


app.get('/v1/orders/:id', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Order retrieval by ID not implemented yet' } });
});

app.get('/v1/orders', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Order list retrieval not implemented yet' } });
});

app.put('/v1/orders/:id/status', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Order status update not implemented yet' } });
});

app.delete('/v1/orders/:id', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Order cancellation not implemented yet' } });
});


// Запуск сервера и миграций
app.listen(PORT, '0.0.0.0', async () => {
  logger.info(`Orders Service запущен на порту ${PORT}`);
  await runMigrations();
});
