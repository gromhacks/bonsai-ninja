const crypto = require('crypto');
const fs = require('fs');


function authMiddleware(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}


function rateLimiter(windowMs, maxRequests) {
    const requests = new Map();

    return function(req, res, next) {
        const key = req.ip;
        const now = Date.now();
        const windowStart = now - windowMs;

        if (!requests.has(key)) {
            requests.set(key, []);
        }

        const timestamps = requests.get(key).filter(t => t > windowStart);
        timestamps.push(now);
        requests.set(key, timestamps);

        if (timestamps.length > maxRequests) {
            return res.status(429).json({ error: 'Too many requests' });
        }

        next();
    };
}


function corsMiddleware(req, res, next) {
    const origin = req.headers.origin;
    const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin || '*');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    next();
}


function errorHandler(err, req, res, next) {
    console.error('Error:', err.stack);
    const statusCode = err.statusCode || 500;
    const message = process.env.NODE_ENV === 'production'
        ? 'Internal Server Error'
        : err.message;
    res.status(statusCode).json({ error: message });
}


function requestLogger(req, res, next) {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logEntry = `${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`;
        // VULN: Log injection - unsanitized user input in logs
        const userAgent = req.headers['user-agent'];
        console.log(`${logEntry} - ${userAgent}`);
    });
    next();
}


function csrfProtection(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    const sessionToken = req.session.csrfToken;
    if (!token || token !== sessionToken) {
        return res.status(403).json({ error: 'CSRF token mismatch' });
    }
    next();
}


function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}


function sanitizeInput(value) {
    if (typeof value !== 'string') return value;
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}


function validateContentType(expectedType) {
    return function(req, res, next) {
        const contentType = req.headers['content-type'];
        if (!contentType || !contentType.includes(expectedType)) {
            return res.status(415).json({ error: `Expected content type: ${expectedType}` });
        }
        next();
    };
}


module.exports = {
    authMiddleware,
    rateLimiter,
    corsMiddleware,
    errorHandler,
    requestLogger,
    csrfProtection,
    generateCsrfToken,
    sanitizeInput,
    validateContentType,
};
