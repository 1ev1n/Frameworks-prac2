const express = require('express');
const proxy = require('express-http-proxy');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const pino = require('pino');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8000;

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// Middleware для добавления Request ID
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || uuidv4();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  logger.info({ requestId, method: req.method, url: req.url }, 'Incoming request');
  next();
});

// CORS
app.use(cors());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per 15 minutes per IP
  message: { success: false, error: { code: 'TOO_MANY_REQUESTS', message: 'Too many requests from this IP, please try again after 15 minutes' } }
});
app.use(limiter);

// Прокси-маршруты
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:3001';
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || 'http://service_orders:3002';

// Приветственный маршрут
app.get('/', (req, res) => {
  res.send('API Gateway is running');
});

app.listen(PORT, () => {
  logger.info(`API Gateway запущен на порту ${PORT}`);
});
