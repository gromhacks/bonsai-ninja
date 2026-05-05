const { ObjectId } = require('mongodb');


class ProductModel {
    constructor(db) {
        this.collection = db.collection('products');
    }

    async findById(id) {
        return this.collection.findOne({ _id: new ObjectId(id) });
    }

    async findAll(filters = {}, options = {}) {
        const cursor = this.collection.find(filters);
        if (options.sort) cursor.sort(options.sort);
        if (options.limit) cursor.limit(options.limit);
        if (options.skip) cursor.skip(options.skip);
        return cursor.toArray();
    }

    async create(data) {
        const result = await this.collection.insertOne({
            ...data,
            createdAt: new Date(),
            updatedAt: new Date(),
        });
        return { _id: result.insertedId, ...data };
    }

    async update(id, data) {
        const result = await this.collection.findOneAndUpdate(
            { _id: new ObjectId(id) },
            { $set: { ...data, updatedAt: new Date() } },
            { returnDocument: 'after' }
        );
        return result.value;
    }

    async delete(id) {
        return this.collection.deleteOne({ _id: new ObjectId(id) });
    }

    async searchByCategory(category) {
        return this.collection.find({ category }).toArray();
    }

    async findByPriceRange(min, max) {
        return this.collection.find({
            price: { $gte: min, $lte: max }
        }).toArray();
    }

    async aggregateStats() {
        return this.collection.aggregate([
            { $group: { _id: '$category', avgPrice: { $avg: '$price' }, count: { $sum: 1 } } },
        ]).toArray();
    }
}


class UserModel {
    constructor(db) {
        this.collection = db.collection('users');
    }

    async findById(id) {
        return this.collection.findOne({ _id: new ObjectId(id) });
    }

    async findByEmail(email) {
        return this.collection.findOne({ email });
    }

    async create(data) {
        const result = await this.collection.insertOne({
            ...data,
            role: 'customer',
            createdAt: new Date(),
        });
        return { _id: result.insertedId, ...data };
    }

    async update(id, data) {
        const result = await this.collection.findOneAndUpdate(
            { _id: new ObjectId(id) },
            { $set: data },
            { returnDocument: 'after' }
        );
        return result.value;
    }

    async findByFilter(filter) {
        // VULN: NoSQL injection if filter comes from user input
        return this.collection.find(filter).toArray();
    }

    async searchUsers(queryObj) {
        // VULN: NoSQL injection - direct query from user
        return this.collection.find(queryObj).toArray();
    }

    async delete(id) {
        return this.collection.deleteOne({ _id: new ObjectId(id) });
    }
}


class OrderModel {
    constructor(db) {
        this.collection = db.collection('orders');
    }

    async findById(id) {
        return this.collection.findOne({ _id: new ObjectId(id) });
    }

    async findByUser(userId) {
        return this.collection.find({ userId: new ObjectId(userId) }).sort({ createdAt: -1 }).toArray();
    }

    async create(data) {
        const result = await this.collection.insertOne({
            ...data,
            createdAt: new Date(),
            updatedAt: new Date(),
        });
        return { _id: result.insertedId, ...data };
    }

    async updateStatus(id, status) {
        return this.collection.findOneAndUpdate(
            { _id: new ObjectId(id) },
            { $set: { status, updatedAt: new Date() } },
            { returnDocument: 'after' }
        );
    }

    async findByDateRange(start, end) {
        return this.collection.find({
            createdAt: { $gte: start, $lte: end }
        }).toArray();
    }

    async aggregateRevenue() {
        return this.collection.aggregate([
            { $match: { status: 'completed' } },
            { $group: { _id: null, total: { $sum: '$total' }, count: { $sum: 1 } } },
        ]).toArray();
    }
}


module.exports = { ProductModel, UserModel, OrderModel };
