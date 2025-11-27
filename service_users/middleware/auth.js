const jwt = require('jsonwebtoken');

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET || 'supersecretjwtkey', (err, user) => {
      if (err) {
        console.warn({ requestId: req.headers['x-request-id'], error: err.message }, 'JWT verification failed');
        return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Invalid or expired token' } });
      }
      req.user = user;
      next();
    });
  } else {
    console.warn({ requestId: req.headers['x-request-id'] }, 'Authentication failed: No token provided');
    res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication token required' } });
  }
};

const authorizeRoles = (roles) => (req, res, next) => {
  if (!req.user || !req.user.roles) {
    console.warn({ requestId: req.headers['x-request-id'], user: req.user }, 'Authorization failed: User roles not found');
    return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'User roles not found' } });
  }

  const hasRole = req.user.roles.some(role => roles.includes(role));
  if (!hasRole) {
    console.warn({ requestId: req.headers['x-request-id'], userId: req.user.id, requiredRoles: roles, userRoles: req.user.roles }, 'Authorization failed: Insufficient permissions');
    return res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Insufficient permissions' } });
  }
  next();
};

module.exports = { authenticateJWT, authorizeRoles };
