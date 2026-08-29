import { Request, Response } from 'express';
import { UserService, PostService, CommentService } from './services';
import { UserRepository, PostRepository } from './repository';
import { WebhookManager, NotificationClient } from './integrations';
import { authGuard, validateInput, sanitizeHtml } from './middleware';

interface Context {
    req: Request;
    res: Response;
    userId?: string;
    db: any;
}

interface UserInput {
    name: string;
    email: string;
    password: string;
    bio?: string;
}

interface PostInput {
    title: string;
    content: string;
    tags: string[];
    published: boolean;
}

interface SearchInput {
    query: string;
    sortBy?: string;
    limit?: number;
    offset?: number;
}


class QueryResolvers {
    private userService: UserService;
    private postService: PostService;

    constructor(db: any) {
        const userRepo = new UserRepository(db);
        const postRepo = new PostRepository(db);
        this.userService = new UserService(userRepo);
        this.postService = new PostService(postRepo);
    }

    async users(args: { search?: string }, ctx: Context): Promise<any[]> {
        if (args.search) {
            return this.userService.searchUsers(args.search);
        }
        return this.userService.listUsers();
    }

    async user(args: { id: string }, ctx: Context): Promise<any> {
        return this.userService.getUserById(args.id);
    }

    async posts(args: SearchInput, ctx: Context): Promise<any[]> {
        return this.postService.searchPosts(args);
    }

    async post(args: { id: string }): Promise<any> {
        return this.postService.getPostById(args.id);
    }

    // VULN: SQL injection via search
    async searchSQL(args: { query: string }, ctx: Context): Promise<any[]> {
        const sql = "SELECT * FROM posts WHERE title LIKE '%" + args.query + "%'";
        return ctx.db.query(sql);
    }

    // Safe version
    async searchSQLSafe(args: { query: string }, ctx: Context): Promise<any[]> {
        return ctx.db.query("SELECT * FROM posts WHERE title LIKE ?", ["%" + args.query + "%"]);
    }
}


class MutationResolvers {
    private userService: UserService;
    private postService: PostService;
    private webhookManager: WebhookManager;

    constructor(db: any) {
        const userRepo = new UserRepository(db);
        const postRepo = new PostRepository(db);
        this.userService = new UserService(userRepo);
        this.postService = new PostService(postRepo);
        this.webhookManager = new WebhookManager();
    }

    async createUser(args: { input: UserInput }, ctx: Context): Promise<any> {
        const user = await this.userService.createUser(args.input);
        await this.webhookManager.notify('user.created', user);
        return user;
    }

    async updateUser(args: { id: string; input: Partial<UserInput> }, ctx: Context): Promise<any> {
        authGuard(ctx);
        return this.userService.updateUser(args.id, args.input);
    }

    async createPost(args: { input: PostInput }, ctx: Context): Promise<any> {
        authGuard(ctx);
        const post = await this.postService.createPost(args.input, ctx.userId!);
        return post;
    }

    async updatePost(args: { id: string; input: Partial<PostInput> }, ctx: Context): Promise<any> {
        authGuard(ctx);
        return this.postService.updatePost(args.id, args.input);
    }

    async deletePost(args: { id: string }, ctx: Context): Promise<boolean> {
        authGuard(ctx);
        return this.postService.deletePost(args.id);
    }

    // VULN: XSS via unsanitized content rendering
    async renderPreview(args: { content: string }, ctx: Context): Promise<string> {
        const html = '<div class="preview">' + args.content + '</div>';
        return html;
    }

    // Safe version
    async renderPreviewSafe(args: { content: string }, ctx: Context): Promise<string> {
        const safe = sanitizeHtml(args.content);
        return '<div class="preview">' + safe + '</div>';
    }

    // VULN: Template injection
    async renderTemplate(args: { template: string; data: any }, ctx: Context): Promise<string> {
        const ejs = require('ejs');
        return ejs.render(args.template, args.data);
    }
}


class AdminResolvers {
    private db: any;

    constructor(db: any) {
        this.db = db;
    }

    // VULN: SQL injection in admin query
    async runQuery(args: { sql: string }, ctx: Context): Promise<any[]> {
        authGuard(ctx);
        const results = await this.db.query(args.sql);
        return results;
    }

    async getStats(ctx: Context): Promise<any> {
        authGuard(ctx);
        const users = await this.db.query("SELECT COUNT(*) as count FROM users");
        const posts = await this.db.query("SELECT COUNT(*) as count FROM posts");
        return { users: users[0].count, posts: posts[0].count };
    }

    // VULN: Command injection
    async runMaintenance(args: { task: string }, ctx: Context): Promise<string> {
        const { exec } = require('child_process');
        return new Promise((resolve, reject) => {
            exec('maintenance-tool ' + args.task, (err: any, stdout: string) => {
                if (err) reject(err);
                else resolve(stdout);
            });
        });
    }

    // VULN: Deserialization
    async importData(args: { data: string }, ctx: Context): Promise<any> {
        const decoded = Buffer.from(args.data, 'base64').toString();
        const parsed = eval('(' + decoded + ')');
        return parsed;
    }
}


function createSchema(db: any) {
    const queries = new QueryResolvers(db);
    const mutations = new MutationResolvers(db);
    const admin = new AdminResolvers(db);

    return {
        Query: {
            users: (parent: any, args: any, ctx: Context) => queries.users(args, ctx),
            user: (parent: any, args: any, ctx: Context) => queries.user(args, ctx),
            posts: (parent: any, args: any, ctx: Context) => queries.posts(args, ctx),
            post: (parent: any, args: any) => queries.post(args),
            searchSQL: (parent: any, args: any, ctx: Context) => queries.searchSQL(args, ctx),
        },
        Mutation: {
            createUser: (parent: any, args: any, ctx: Context) => mutations.createUser(args, ctx),
            updateUser: (parent: any, args: any, ctx: Context) => mutations.updateUser(args, ctx),
            createPost: (parent: any, args: any, ctx: Context) => mutations.createPost(args, ctx),
            renderPreview: (parent: any, args: any, ctx: Context) => mutations.renderPreview(args, ctx),
            renderTemplate: (parent: any, args: any, ctx: Context) => mutations.renderTemplate(args, ctx),
        },
        Admin: {
            runQuery: (parent: any, args: any, ctx: Context) => admin.runQuery(args, ctx),
            runMaintenance: (parent: any, args: any, ctx: Context) => admin.runMaintenance(args, ctx),
            importData: (parent: any, args: any, ctx: Context) => admin.importData(args, ctx),
        },
    };
}

export { createSchema, QueryResolvers, MutationResolvers, AdminResolvers, Context, UserInput, PostInput, SearchInput };
