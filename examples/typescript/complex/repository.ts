
class QueryBuilder {
    private table: string;
    private conditions: string[];
    private orderClause: string;
    private limitVal: number;
    private offsetVal: number;

    constructor(table: string) {
        this.table = table;
        this.conditions = [];
        this.orderClause = '';
        this.limitVal = 0;
        this.offsetVal = 0;
    }

    where(condition: string): QueryBuilder {
        this.conditions.push(condition);
        return this;
    }

    orderBy(field: string, direction: string = 'ASC'): QueryBuilder {
        this.orderClause = `ORDER BY ${field} ${direction}`;
        return this;
    }

    limit(n: number): QueryBuilder {
        this.limitVal = n;
        return this;
    }

    offset(n: number): QueryBuilder {
        this.offsetVal = n;
        return this;
    }

    build(): string {
        let sql = `SELECT * FROM ${this.table}`;
        if (this.conditions.length > 0) {
            sql += ' WHERE ' + this.conditions.join(' AND ');
        }
        if (this.orderClause) {
            sql += ' ' + this.orderClause;
        }
        if (this.limitVal > 0) {
            sql += ` LIMIT ${this.limitVal}`;
        }
        if (this.offsetVal > 0) {
            sql += ` OFFSET ${this.offsetVal}`;
        }
        return sql;
    }
}


class UserRepository {
    private db: any;

    constructor(db: any) {
        this.db = db;
    }

    async findById(id: string): Promise<any> {
        const results = await this.db.query("SELECT * FROM users WHERE id = ?", [id]);
        return results[0] || null;
    }

    async findByEmail(email: string): Promise<any> {
        const results = await this.db.query("SELECT * FROM users WHERE email = ?", [email]);
        return results[0] || null;
    }

    async findAll(): Promise<any[]> {
        return this.db.query("SELECT * FROM users ORDER BY created_at DESC");
    }

    async create(data: any): Promise<any> {
        const result = await this.db.query(
            "INSERT INTO users (name, email, password_hash, bio) VALUES (?, ?, ?, ?)",
            [data.name, data.email, data.passwordHash, data.bio]
        );
        return { id: result.insertId, ...data };
    }

    async update(id: string, data: any): Promise<any> {
        const fields = Object.keys(data).map(k => `${k} = ?`).join(', ');
        const values = [...Object.values(data), id];
        await this.db.query(`UPDATE users SET ${fields} WHERE id = ?`, values);
        return this.findById(id);
    }

    async delete(id: string): Promise<boolean> {
        const result = await this.db.query("DELETE FROM users WHERE id = ?", [id]);
        return result.affectedRows > 0;
    }

    // VULN: SQL injection in user search
    async search(query: string): Promise<any[]> {
        const sql = "SELECT * FROM users WHERE name LIKE '%" + query + "%' OR email LIKE '%" + query + "%'";
        return this.db.query(sql);
    }

    // Safe version
    async searchSafe(query: string): Promise<any[]> {
        return this.db.query(
            "SELECT * FROM users WHERE name LIKE ? OR email LIKE ?",
            ["%" + query + "%", "%" + query + "%"]
        );
    }
}


class PostRepository {
    private db: any;

    constructor(db: any) {
        this.db = db;
    }

    async findById(id: string): Promise<any> {
        const results = await this.db.query("SELECT * FROM posts WHERE id = ?", [id]);
        return results[0] || null;
    }

    async findAll(): Promise<any[]> {
        return this.db.query("SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC");
    }

    async create(data: any): Promise<any> {
        const result = await this.db.query(
            "INSERT INTO posts (title, content, author_id, tags, published) VALUES (?, ?, ?, ?, ?)",
            [data.title, data.content, data.authorId, JSON.stringify(data.tags), data.published]
        );
        return { id: result.insertId, ...data };
    }

    async update(id: string, data: any): Promise<any> {
        const fields = Object.keys(data).map(k => `${k} = ?`).join(', ');
        const values = [...Object.values(data), id];
        await this.db.query(`UPDATE posts SET ${fields} WHERE id = ?`, values);
        return this.findById(id);
    }

    async delete(id: string): Promise<boolean> {
        const result = await this.db.query("DELETE FROM posts WHERE id = ?", [id]);
        return result.affectedRows > 0;
    }

    async findByAuthor(authorId: string): Promise<any[]> {
        return this.db.query("SELECT * FROM posts WHERE author_id = ? ORDER BY created_at DESC", [authorId]);
    }

    async findByTag(tag: string): Promise<any[]> {
        return this.db.query("SELECT * FROM posts WHERE tags LIKE ?", ["%" + tag + "%"]);
    }

    // VULN: SQL injection in search
    async search(params: { query: string; sortBy?: string; limit?: number; offset?: number }): Promise<any[]> {
        const qb = new QueryBuilder('posts');
        qb.where("title LIKE '%" + params.query + "%'");
        if (params.sortBy) {
            qb.orderBy(params.sortBy);
        }
        if (params.limit) {
            qb.limit(params.limit);
        }
        if (params.offset) {
            qb.offset(params.offset);
        }
        const sql = qb.build();
        return this.db.query(sql);
    }

    // Safe version
    async searchSafe(params: { query: string }): Promise<any[]> {
        return this.db.query("SELECT * FROM posts WHERE title LIKE ?", ["%" + params.query + "%"]);
    }
}


export { UserRepository, PostRepository, QueryBuilder };
