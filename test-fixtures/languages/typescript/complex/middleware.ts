import * as crypto from 'crypto';

interface MiddlewareContext {
    req: any;
    res: any;
    userId?: string;
}

function authGuard(ctx: MiddlewareContext): void {
    if (!ctx.userId) {
        throw new Error('Authentication required');
    }
}


function validateInput(input: any, schema: Record<string, string>): boolean {
    for (const [field, type] of Object.entries(schema)) {
        if (typeof input[field] !== type) {
            throw new Error(`Invalid field: ${field} expected ${type}`);
        }
    }
    return true;
}


function sanitizeHtml(html: string): string {
    return html
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}


function verifyJWT(token: string): any {
    const secret = process.env.JWT_SECRET || 'dev-secret';
    const [header, payload, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', secret).update(header + '.' + payload).digest('base64');
    if (signature !== expected) {
        throw new Error('Invalid token');
    }
    return JSON.parse(Buffer.from(payload, 'base64').toString());
}


function rateLimiter(windowMs: number, maxRequests: number) {
    const requests = new Map<string, number[]>();

    return function(req: any, res: any, next: () => void): void {
        const key = req.ip;
        const now = Date.now();
        const windowStart = now - windowMs;

        if (!requests.has(key)) {
            requests.set(key, []);
        }

        const timestamps = requests.get(key)!.filter(t => t > windowStart);
        timestamps.push(now);
        requests.set(key, timestamps);

        if (timestamps.length > maxRequests) {
            res.status(429).json({ error: 'Too many requests' });
            return;
        }
        next();
    };
}


function corsHandler(allowedOrigins: string[]) {
    return function(req: any, res: any, next: () => void): void {
        const origin = req.headers.origin;
        if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin || '*');
        }
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
        next();
    };
}


function requestLogger(req: any, res: any, next: () => void): void {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.url} ${res.statusCode} ${duration}ms`);
    });
    next();
}


function errorHandler(err: Error, req: any, res: any, next: () => void): void {
    console.error('Error:', err.message);
    res.status(500).json({ error: err.message });
}


function parseAuthToken(req: any): string | null {
    const auth = req.headers.authorization;
    if (!auth) return null;
    const [type, token] = auth.split(' ');
    if (type !== 'Bearer') return null;
    return token;
}


export { authGuard, validateInput, sanitizeHtml, verifyJWT, rateLimiter, corsHandler, requestLogger, errorHandler, parseAuthToken };
