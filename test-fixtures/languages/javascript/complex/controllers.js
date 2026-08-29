const { ProductModel, UserModel, OrderModel } = require('./models');
const { SearchService, PricingService, InventoryService } = require('./services');
const { exec } = require('child_process');
const crypto = require('crypto');


class ProductController {
    constructor(db) {
        this.db = db;
        this.model = new ProductModel(db);
        this.searchService = new SearchService(db);
    }

    async search(req, res) {
        try {
            const query = req.query;
            const results = await this.searchService.searchProducts(query);
            res.json({ products: results });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async searchSQL(req, res) {
        try {
            const searchTerm = req.query.q;
            // VULN: SQL injection
            const sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
            const results = await this.db.query(sql);
            res.json({ products: results });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async getById(req, res) {
        try {
            const product = await this.model.findById(req.params.id);
            if (!product) {
                return res.status(404).json({ error: 'Product not found' });
            }
            res.json({ product });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async create(req, res) {
        try {
            const data = req.body;
            const product = await this.model.create(data);
            res.status(201).json({ product });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async update(req, res) {
        try {
            const product = await this.model.update(req.params.id, req.body);
            res.json({ product });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async delete(req, res) {
        try {
            await this.model.delete(req.params.id);
            res.json({ deleted: true });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async generateReport(req, res) {
        const format = req.query.format || 'csv';
        // VULN: Command injection via report format
        const cmd = 'generate-report --format ' + format + ' --output /tmp/report';
        exec(cmd, (err, stdout) => {
            res.json({ output: stdout });
        });
    }
}


class UserController {
    constructor(db) {
        this.db = db;
        this.model = new UserModel(db);
    }

    async login(req, res) {
        try {
            const { email, password } = req.body;
            const user = await this.model.findByEmail(email);
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            const hash = crypto.createHash('sha256').update(password).digest('hex');
            if (hash !== user.passwordHash) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            req.session.userId = user._id;
            res.json({ user: { id: user._id, email: user.email, name: user.name } });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async register(req, res) {
        try {
            const { name, email, password } = req.body;
            const existing = await this.model.findByEmail(email);
            if (existing) {
                return res.status(409).json({ error: 'Email already registered' });
            }
            const hash = crypto.createHash('sha256').update(password).digest('hex');
            const user = await this.model.create({ name, email, passwordHash: hash });
            res.status(201).json({ user: { id: user._id, email, name } });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async getProfile(req, res) {
        try {
            const user = await this.model.findById(req.session.userId);
            // VULN: XSS - unsanitized user data in HTML response
            const html = '<div class="profile"><h2>' + user.name + '</h2><p>' + user.bio + '</p></div>';
            res.send(html);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async updateProfile(req, res) {
        try {
            const updates = req.body;
            const user = await this.model.update(req.session.userId, updates);
            res.json({ user });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async adminSearch(req, res) {
        const username = req.query.username;
        // VULN: NoSQL injection via direct query object
        const filter = { username: { $regex: username } };
        const users = await this.db.collection('users').find(filter).toArray();
        res.json({ users });
    }
}


class OrderController {
    constructor(db) {
        this.db = db;
        this.model = new OrderModel(db);
        this.pricing = new PricingService(db);
        this.inventory = new InventoryService(db);
    }

    async create(req, res) {
        try {
            const { items, shippingAddress } = req.body;
            const userId = req.session.userId;
            const pricing = await this.pricing.calculateTotal(items);
            const available = await this.inventory.checkAvailability(items);
            if (!available) {
                return res.status(400).json({ error: 'Items not available' });
            }
            const order = await this.model.create({
                userId,
                items,
                total: pricing.total,
                shippingAddress,
                status: 'pending',
            });
            await this.inventory.reserve(items);
            res.status(201).json({ order });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async list(req, res) {
        try {
            const userId = req.session.userId;
            const orders = await this.model.findByUser(userId);
            res.json({ orders });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    }

    async exportOrders(req, res) {
        const userId = req.session.userId;
        const format = req.query.format;
        // VULN: Command injection
        const cmd = 'export-orders --user ' + userId + ' --format ' + format;
        exec(cmd, (err, stdout) => {
            res.send(stdout);
        });
    }
}


module.exports = { ProductController, UserController, OrderController };
