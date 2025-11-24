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

// JWT Authentication middleware (placeholder for now)
const authenticateJWT = (req, res, next) => {
  // For simplicity, allow /v1/register and /v1/login to bypass JWT check at Gateway
  if (req.path === '/v1/register' || req.path === '/v1/login') {
    return next();
  }

  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    // In a real scenario, you'd verify the token here
    // For now, we'll just pass it through or simulate success
    // For now, we'll just mock the user based on the presence of a token
    req.user = { id: 'mock-user-id', roles: ['user'] }; // Mock user
    req.headers['x-user-id'] = req.user.id;
    req.headers['x-user-roles'] = JSON.stringify(req.user.roles);
    next();
  } else {
    logger.warn({ requestId: req.requestId }, 'Authentication failed: No token provided');
    res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication token required' } });
  }
};

// Прокси-маршруты
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:3001';
const ORDERS_SERVICE_URL = process.env.ORDERS_SERVICE_URL || 'http://service_orders:3002';

// Приветственный маршрут
app.get('/', (req, res) => {
  res.send('API Gateway is running');
});

// Открытые маршруты для Users Service (регистрация и логин не требуют JWT на уровне Gateway)
app.post('/v1/register', proxy(USERS_SERVICE_URL));
app.post('/v1/login', proxy(USERS_SERVICE_URL));

// Защищенные маршруты (требуют JWT)
app.use('/users', authenticateJWT, proxy(USERS_SERVICE_URL));
app.use('/orders', authenticateJWT, proxy(ORDERS_SERVICE_URL));

app.listen(PORT, () => {
  logger.info(`API Gateway запущен на порту ${PORT}`);
});
