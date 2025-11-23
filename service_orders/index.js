const express = require('express');
const cors = require('cors');
const pino = require('pino');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const db = require('./src/db'); // Подключаем наш модуль для работы с БД

const app = express();
const PORT = process.env.PORT || 3002; // Изменен порт для сервиса заказов

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

// TODO: Реализовать остальные маршруты
app.post('/v1/orders', (req, res) => {
  res.status(501).json({ success: false, error: { code: 'NOT_IMPLEMENTED', message: 'Order creation not implemented yet' } });
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
