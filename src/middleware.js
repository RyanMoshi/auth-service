'use strict';

function createMiddleware(authService) {
  return function authMiddleware(req, res, next) {
    const header = req.headers && req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }
    try {
      req.user = authService.verify(header.slice(7));
      next();
    } catch (err) {
      res.status(401).json({ error: err.message });
    }
  };
}

module.exports = createMiddleware;
