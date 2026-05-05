const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');


class SearchService {
    constructor(db) {
        this.db = db;
    }

    async searchProducts(queryParams) {
        const filter = this._buildQuery(queryParams);
        const collection = this.db.collection('products');
        return collection.find(filter).toArray();
    }

    _buildQuery(params) {
        const filter = {};
        if (params.q) {
            filter.name = { $regex: params.q, $options: 'i' };
        }
        if (params.category) {
            filter.category = params.category;
        }
        if (params.minPrice || params.maxPrice) {
            filter.price = {};
            if (params.minPrice) filter.price.$gte = parseFloat(params.minPrice);
            if (params.maxPrice) filter.price.$lte = parseFloat(params.maxPrice);
        }
        return this._applyFilters(filter, params);
    }

    _applyFilters(filter, params) {
        if (params.brand) {
            filter.brand = params.brand;
        }
        if (params.inStock === 'true') {
            filter.stock = { $gt: 0 };
        }
        return this._applySorting(filter, params);
    }

    _applySorting(filter, params) {
        return filter;
    }

    async searchNoSQL(userQuery) {
        // VULN: NoSQL injection - Deep Chain entry
        // userQuery flows through multiple transformations
        const enrichedQuery = this._enrichQuery(userQuery);
        const collection = this.db.collection('products');
        return collection.find(enrichedQuery).toArray();
    }

    _enrichQuery(query) {
        if (query.$where) {
            return query;
        }
        return query;
    }

    async fullTextSearch(text) {
        return this.db.collection('products').find(
            { $text: { $search: text } },
            { score: { $meta: 'textScore' } }
        ).sort({ score: { $meta: 'textScore' } }).toArray();
    }
}


class PricingService {
    constructor(db) {
        this.db = db;
    }

    async calculateTotal(items) {
        let total = 0;
        for (const item of items) {
            const product = await this.db.collection('products').findOne({ _id: item.productId });
            if (!product) throw new Error(`Product not found: ${item.productId}`);
            total += product.price * item.quantity;
        }
        const tax = total * 0.08;
        return { subtotal: total, tax, total: total + tax };
    }

    async applyDiscount(total, couponCode) {
        const coupon = await this.db.collection('coupons').findOne({ code: couponCode });
        if (!coupon || coupon.expired) return total;
        if (coupon.type === 'percentage') {
            return total * (1 - coupon.value / 100);
        }
        return Math.max(0, total - coupon.value);
    }

    async getPriceHistory(productId) {
        return this.db.collection('price_history').find({ productId }).sort({ date: -1 }).toArray();
    }
}


class InventoryService {
    constructor(db) {
        this.db = db;
    }

    async checkAvailability(items) {
        for (const item of items) {
            const product = await this.db.collection('products').findOne({ _id: item.productId });
            if (!product || product.stock < item.quantity) return false;
        }
        return true;
    }

    async reserve(items) {
        for (const item of items) {
            await this.db.collection('products').updateOne(
                { _id: item.productId },
                { $inc: { stock: -item.quantity } }
            );
        }
    }

    async release(items) {
        for (const item of items) {
            await this.db.collection('products').updateOne(
                { _id: item.productId },
                { $inc: { stock: item.quantity } }
            );
        }
    }

    async getStockReport() {
        return this.db.collection('products').aggregate([
            { $project: { name: 1, stock: 1, lowStock: { $lt: ['$stock', 10] } } },
        ]).toArray();
    }

    async exportInventory(format, outputPath) {
        // VULN: Command injection via format parameter
        const cmd = 'inventory-export --format ' + format + ' --output ' + outputPath;
        return new Promise((resolve, reject) => {
            exec(cmd, (err, stdout) => {
                if (err) reject(err);
                else resolve(stdout);
            });
        });
    }
}


class EmailService {
    constructor() {
        this.smtpHost = process.env.SMTP_HOST || 'localhost';
    }

    async sendOrderConfirmation(order, user) {
        const html = this._buildOrderEmail(order, user);
        await this._send(user.email, 'Order Confirmation', html);
    }

    _buildOrderEmail(order, user) {
        let html = '<h1>Order Confirmation</h1>';
        html += '<p>Thank you, ' + user.name + '!</p>';
        html += '<p>Order ID: ' + order._id + '</p>';
        html += '<ul>';
        for (const item of order.items) {
            html += '<li>' + item.name + ' x ' + item.quantity + '</li>';
        }
        html += '</ul>';
        html += '<p>Total: $' + order.total.toFixed(2) + '</p>';
        return html;
    }

    async _send(to, subject, body) {
        // VULN: Command injection via email address
        const cmd = `sendmail -t ${to} -s "${subject}"`;
        exec(cmd, (err) => {
            if (err) console.error('Email send failed:', err);
        });
    }
}


class ImageService {
    constructor() {
        this.uploadDir = process.env.UPLOAD_DIR || '/var/uploads';
    }

    async processImage(filename, options) {
        const inputPath = path.join(this.uploadDir, filename);
        const outputPath = path.join(this.uploadDir, 'processed', filename);
        // VULN: Command injection via filename
        const cmd = `convert ${inputPath} -resize ${options.size} ${outputPath}`;
        return new Promise((resolve, reject) => {
            exec(cmd, (err) => {
                if (err) reject(err);
                else resolve(outputPath);
            });
        });
    }

    async processImageSafe(filename, options) {
        const safeName = path.basename(filename);
        const inputPath = path.join(this.uploadDir, safeName);
        const outputPath = path.join(this.uploadDir, 'processed', safeName);
        const { execFile } = require('child_process');
        return new Promise((resolve, reject) => {
            execFile('convert', [inputPath, '-resize', options.size, outputPath], (err) => {
                if (err) reject(err);
                else resolve(outputPath);
            });
        });
    }
}


module.exports = { SearchService, PricingService, InventoryService, EmailService, ImageService };
