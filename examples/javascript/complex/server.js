const express = require('express');
const { MongoClient } = require('mongodb');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const { ProductController, UserController, OrderController } = require('./controllers');
const { authMiddleware, rateLimiter, errorHandler } = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/ecommerce';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
}));

let db;

async function connectDB() {
    const client = await MongoClient.connect(MONGO_URI);
    db = client.db('ecommerce');
    return db;
}

// Public routes
app.get('/api/products/search', (req, res) => {
    const controller = new ProductController(db);
    controller.search(req, res);
});

app.get('/api/products/:id', (req, res) => {
    const controller = new ProductController(db);
    controller.getById(req, res);
});

app.post('/api/auth/login', (req, res) => {
    const controller = new UserController(db);
    controller.login(req, res);
});

app.post('/api/auth/register', (req, res) => {
    const controller = new UserController(db);
    controller.register(req, res);
});

// Protected routes
app.use('/api/orders', authMiddleware);
app.post('/api/orders', (req, res) => {
    const controller = new OrderController(db);
    controller.create(req, res);
});

app.get('/api/orders', (req, res) => {
    const controller = new OrderController(db);
    controller.list(req, res);
});

// Admin routes
app.get('/admin/dashboard', (req, res) => {
    const search = req.query.search || '';
    // VULN: XSS - unsanitized search in response
    res.send('<h1>Admin Dashboard</h1><p>Search: ' + search + '</p>');
});

app.get('/admin/dashboard/safe', (req, res) => {
    const search = req.query.search || '';
    const escaped = search.replace(/[<>&"']/g, c => `&#${c.charCodeAt(0)};`);
    res.send('<h1>Admin Dashboard</h1><p>Search: ' + escaped + '</p>');
});

// VULN: Open redirect
app.get('/redirect', (req, res) => {
    const target = req.query.url;
    res.redirect(target);
});

// VULN: Path traversal - serving user-controlled files
app.get('/api/files/download', (req, res) => {
    const filename = req.query.filename;
    const filepath = path.join('/var/uploads', filename);
    res.sendFile(filepath);
});

// Safe file download
app.get('/api/files/download/safe', (req, res) => {
    const filename = path.basename(req.query.filename);
    const filepath = path.join('/var/uploads', filename);
    res.sendFile(filepath);
});

// VULN: SSRF via proxy
app.get('/api/proxy', async (req, res) => {
    const axios = require('axios');
    const targetUrl = req.query.url;
    const response = await axios.get(targetUrl);
    res.json(response.data);
});

// VULN: Command injection
app.post('/api/admin/system', (req, res) => {
    const { exec } = require('child_process');
    const command = req.body.command;
    exec(command, (error, stdout, stderr) => {
        res.json({ output: stdout, error: stderr });
    });
});

// Safe command execution
app.post('/api/admin/system/safe', (req, res) => {
    const { execFile } = require('child_process');
    const allowed = ['df', 'uptime', 'whoami'];
    const command = req.body.command;
    if (!allowed.includes(command)) {
        return res.status(400).json({ error: 'Command not allowed' });
    }
    execFile(command, (error, stdout) => {
        res.json({ output: stdout });
    });
});

// VULN: Prototype pollution via deep merge
app.post('/api/settings', (req, res) => {
    const _ = require('lodash');
    const defaults = { theme: 'light', lang: 'en' };
    const settings = _.merge(defaults, req.body);
    res.json(settings);
});

// VULN: Deserialization
app.post('/api/import', (req, res) => {
    const data = Buffer.from(req.body.data, 'base64').toString();
    const obj = eval('(' + data + ')');
    res.json({ imported: obj });
});

// VULN: Regex DoS
app.post('/api/validate/email', (req, res) => {
    const email = req.body.email;
    const regex = new RegExp('^([a-zA-Z0-9_\\-\\.]+)*@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$');
    const valid = regex.test(email);
    res.json({ valid });
});

app.use(errorHandler);

async function main() {
    await connectDB();
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

main().catch(console.error);

module.exports = { app, connectDB };
