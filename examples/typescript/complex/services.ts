import * as crypto from 'crypto';
import { UserRepository, PostRepository } from './repository';

interface UserRecord {
    id: string;
    name: string;
    email: string;
    passwordHash: string;
    bio?: string;
    createdAt: Date;
}

interface PostRecord {
    id: string;
    title: string;
    content: string;
    authorId: string;
    tags: string[];
    published: boolean;
    createdAt: Date;
}


class UserService {
    private repo: UserRepository;

    constructor(repo: UserRepository) {
        this.repo = repo;
    }

    async createUser(input: { name: string; email: string; password: string; bio?: string }): Promise<UserRecord> {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(input.password, salt, 100000, 64, 'sha512').toString('hex');
        return this.repo.create({
            name: input.name,
            email: input.email,
            passwordHash: salt + ':' + hash,
            bio: input.bio,
        });
    }

    async authenticate(email: string, password: string): Promise<UserRecord | null> {
        const user = await this.repo.findByEmail(email);
        if (!user) return null;
        const [salt, storedHash] = user.passwordHash.split(':');
        const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
        if (hash !== storedHash) return null;
        return user;
    }

    async getUserById(id: string): Promise<UserRecord | null> {
        return this.repo.findById(id);
    }

    async listUsers(): Promise<UserRecord[]> {
        return this.repo.findAll();
    }

    async searchUsers(query: string): Promise<UserRecord[]> {
        return this.repo.search(query);
    }

    async updateUser(id: string, updates: Partial<UserRecord>): Promise<UserRecord> {
        return this.repo.update(id, updates);
    }

    async deleteUser(id: string): Promise<boolean> {
        return this.repo.delete(id);
    }

    generateJWT(user: UserRecord): string {
        const payload = { id: user.id, email: user.email };
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
        const body = Buffer.from(JSON.stringify(payload)).toString('base64');
        const secret = process.env.JWT_SECRET || 'dev-secret';
        const signature = crypto.createHmac('sha256', secret).update(header + '.' + body).digest('base64');
        return header + '.' + body + '.' + signature;
    }
}


class PostService {
    private repo: PostRepository;

    constructor(repo: PostRepository) {
        this.repo = repo;
    }

    async createPost(input: { title: string; content: string; tags: string[]; published: boolean }, authorId: string): Promise<PostRecord> {
        return this.repo.create({
            title: input.title,
            content: input.content,
            authorId,
            tags: input.tags,
            published: input.published,
        });
    }

    async getPostById(id: string): Promise<PostRecord | null> {
        return this.repo.findById(id);
    }

    async searchPosts(params: { query: string; sortBy?: string; limit?: number; offset?: number }): Promise<PostRecord[]> {
        return this.repo.search(params);
    }

    async updatePost(id: string, updates: Partial<PostRecord>): Promise<PostRecord> {
        return this.repo.update(id, updates);
    }

    async deletePost(id: string): Promise<boolean> {
        return this.repo.delete(id);
    }

    async getPostsByAuthor(authorId: string): Promise<PostRecord[]> {
        return this.repo.findByAuthor(authorId);
    }

    async getPostsByTag(tag: string): Promise<PostRecord[]> {
        return this.repo.findByTag(tag);
    }

    async publishPost(id: string): Promise<PostRecord> {
        return this.repo.update(id, { published: true } as any);
    }
}


class CommentService {
    private db: any;

    constructor(db: any) {
        this.db = db;
    }

    async createComment(postId: string, authorId: string, content: string): Promise<any> {
        const result = await this.db.query(
            "INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)",
            [postId, authorId, content]
        );
        return { id: result.insertId, postId, authorId, content };
    }

    async getComments(postId: string): Promise<any[]> {
        return this.db.query("SELECT * FROM comments WHERE post_id = ?", [postId]);
    }

    // VULN: SQL injection in comment search
    async searchComments(searchTerm: string): Promise<any[]> {
        const sql = "SELECT * FROM comments WHERE content LIKE '%" + searchTerm + "%'";
        return this.db.query(sql);
    }

    // Safe version
    async searchCommentsSafe(searchTerm: string): Promise<any[]> {
        return this.db.query("SELECT * FROM comments WHERE content LIKE ?", ["%" + searchTerm + "%"]);
    }

    async deleteComment(id: string): Promise<boolean> {
        const result = await this.db.query("DELETE FROM comments WHERE id = ?", [id]);
        return result.affectedRows > 0;
    }
}


class AnalyticsService {
    private db: any;

    constructor(db: any) {
        this.db = db;
    }

    async trackPageView(postId: string, userId: string, metadata: any): Promise<void> {
        await this.db.query(
            "INSERT INTO analytics (post_id, user_id, event, metadata) VALUES (?, ?, 'view', ?)",
            [postId, userId, JSON.stringify(metadata)]
        );
    }

    async getPostAnalytics(postId: string): Promise<any> {
        const views = await this.db.query(
            "SELECT COUNT(*) as count FROM analytics WHERE post_id = ? AND event = 'view'",
            [postId]
        );
        return { postId, views: views[0].count };
    }

    // VULN: SQL injection in analytics query
    async customQuery(query: string): Promise<any[]> {
        const sql = "SELECT * FROM analytics WHERE " + query;
        return this.db.query(sql);
    }
}


export { UserService, PostService, CommentService, AnalyticsService, UserRecord, PostRecord };
