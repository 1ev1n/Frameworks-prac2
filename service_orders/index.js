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

// Схема валидации для обновления статуса заказа
const updateOrderStatusSchema = Joi.object({
  status: Joi.string().valid('created', 'in_progress', 'completed', 'cancelled').required(),
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
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');

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

// Маршрут получения заказа по ID
app.get('/v1/orders/:id', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    const { id } = req.params;
    const userId = req.headers['x-user-id'];
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');

    const order = await db.query('SELECT id, user_id, items, status, total_amount, created_at, updated_at FROM orders WHERE id = $1', [id]);

    if (order.rows.length === 0) {
      logger.warn({ requestId, orderId: id }, 'Order not found');
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Order not found' } });
    }

    const fetchedOrder = order.rows[0];

    // Только владелец заказа или администратор могут просматривать заказ
    if (fetchedOrder.user_id !== userId && !userRoles.includes('admin')) {
      logger.warn({ requestId, orderId: id, userId, userRoles }, 'Unauthorized access to order');
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions' } });
    }

    logger.info({ requestId, orderId: id }, 'Order retrieved successfully');
    res.status(200).json({ success: true, data: fetchedOrder });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error retrieving order by ID');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Маршрут получения списка заказов с пагинацией и сортировкой
app.get('/v1/orders', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const sortBy = req.query.sortBy || 'created_at'; // По умолчанию сортируем по дате создания
    const sortOrder = req.query.sortOrder === 'asc' ? 'ASC' : 'DESC';

    const userId = req.headers['x-user-id'];
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');

    let query = 'SELECT id, user_id, items, status, total_amount, created_at, updated_at FROM orders';
    let countQuery = 'SELECT COUNT(*) FROM orders';
    const queryParams = [];
    const countParams = [];
    let paramIndex = 1;

    // Если пользователь не администратор, то показываем только его заказы
    if (!userRoles.includes('admin')) {
      query += ` WHERE user_id = $${paramIndex}`; // Используем user_id из токена
      countQuery += ` WHERE user_id = $${paramIndex}`; // Используем user_id из токена
      queryParams.push(userId);
      countParams.push(userId);
      paramIndex++;
    }

    query += ` ORDER BY ${sortBy} ${sortOrder} LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    queryParams.push(limit, offset);

    const orders = await db.query(query, queryParams);
    const totalOrders = await db.query(countQuery, countParams);
    const total = parseInt(totalOrders.rows[0].count);

    logger.info({ requestId, page, limit, total, sortBy, sortOrder }, 'Orders list retrieved successfully');
    res.status(200).json({ success: true, data: orders.rows, pagination: { total, page, limit, sortBy, sortOrder } });

  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error retrieving orders list');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Маршрут обновления статуса заказа
app.put('/v1/orders/:id/status', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    const { id } = req.params;
    const { error, value } = updateOrderStatusSchema.validate(req.body);
    if (error) {
      logger.error({ requestId, error: error.details[0].message }, 'Validation error for order status update');
      return res.status(400).json({ success: false, error: { code: 'VALIDATION_ERROR', message: error.details[0].message } });
    }
    const { status } = value;

    const userId = req.headers['x-user-id'];
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');

    const order = await db.query('SELECT user_id, status FROM orders WHERE id = $1', [id]);

    if (order.rows.length === 0) {
      logger.warn({ requestId, orderId: id }, 'Order not found for status update');
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Order not found' } });
    }

    const fetchedOrder = order.rows[0];

    // Только администратор может менять статус любого заказа
    // Владелец заказа может отменить свой заказ, если он в статусе 'created' или 'in_progress'
    if (!userRoles.includes('admin')) {
      if (fetchedOrder.user_id !== userId) {
        logger.warn({ requestId, orderId: id, userId, userRoles }, 'Unauthorized access to update order status');
        return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions' } });
      }
      if (status === 'cancelled' && (fetchedOrder.status === 'created' || fetchedOrder.status === 'in_progress')) {
        // Владелец может отменить свой заказ
      } else if (status !== 'cancelled') {
        logger.warn({ requestId, orderId: id, userId, userRoles, newStatus: status }, 'User tried to change status to something other than cancelled without admin privileges');
        return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Only admin can change order status to this value' } });
      }
    }

    const updatedOrder = await db.query(
      'UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, user_id, items, status, total_amount, created_at, updated_at',
      [status, id]
    );

    logger.info({ requestId, orderId: id, newStatus: status }, 'Order status updated successfully');
    res.status(200).json({ success: true, data: updatedOrder.rows[0] });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error updating order status');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});

// Маршрут отмены заказа
app.delete('/v1/orders/:id', authenticateJWT, async (req, res) => {
  const requestId = req.requestId;
  try {
    const { id } = req.params;
    const userId = req.headers['x-user-id'];
    const userRoles = JSON.parse(req.headers['x-user-roles'] || '[]');

    const order = await db.query('SELECT user_id, status FROM orders WHERE id = $1', [id]);

    if (order.rows.length === 0) {
      logger.warn({ requestId, orderId: id }, 'Order not found for cancellation');
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Order not found' } });
    }

    const fetchedOrder = order.rows[0];

    // Только администратор или владелец заказа могут удалить заказ
    if (fetchedOrder.user_id !== userId && !userRoles.includes('admin')) {
      logger.warn({ requestId, orderId: id, userId, userRoles }, 'Unauthorized access to cancel order');
      return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions' } });
    }

    // Заказ можно отменить, только если он не в статусе 'completed'
    if (fetchedOrder.status === 'completed') {
      logger.warn({ requestId, orderId: id, currentStatus: fetchedOrder.status }, 'Cannot cancel a completed order');
      return res.status(400).json({ success: false, error: { code: 'INVALID_STATUS', message: 'Cannot cancel a completed order' } });
    }

    const deletedOrder = await db.query(
      'DELETE FROM orders WHERE id = $1 RETURNING id',
      [id]
    );

    if (deletedOrder.rows.length === 0) {
      logger.warn({ requestId, orderId: id }, 'Order not found during deletion attempt');
      return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Order not found for deletion' } });
    }

    logger.info({ requestId, orderId: id }, 'Order cancelled successfully');
    res.status(200).json({ success: true, data: { id: deletedOrder.rows[0].id, status: 'cancelled' } });
  } catch (error) {
    logger.error({ requestId, error: error.message }, 'Error cancelling order');
    res.status(500).json({ success: false, error: { code: 'SERVER_ERROR', message: 'Internal server error' } });
  }
});


// Запуск сервера и миграций
app.listen(PORT, '0.0.0.0', async () => {
  logger.info(`Orders Service запущен на порту ${PORT}`);
  await runMigrations();
});
