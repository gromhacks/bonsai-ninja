import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';

interface WebhookConfig {
    url: string;
    secret: string;
    events: string[];
}

interface NotificationPayload {
    type: string;
    message: string;
    data: any;
}


class WebhookManager {
    private webhooks: WebhookConfig[];

    constructor() {
        this.webhooks = [];
    }

    register(config: WebhookConfig): void {
        this.webhooks.push(config);
    }

    async notify(event: string, data: any): Promise<void> {
        const relevant = this.webhooks.filter(w => w.events.includes(event));
        for (const webhook of relevant) {
            await this._send(webhook, event, data);
        }
    }

    // VULN: SSRF - webhook URL is user-controlled
    async _send(webhook: WebhookConfig, event: string, data: any): Promise<void> {
        const axios = require('axios');
        const payload = JSON.stringify({ event, data, timestamp: Date.now() });
        await axios.post(webhook.url, payload, {
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // Safe version with URL validation
    async _sendSafe(webhook: WebhookConfig, event: string, data: any): Promise<void> {
        const url = new URL(webhook.url);
        const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'];
        if (blocked.includes(url.hostname)) {
            throw new Error('Blocked webhook URL');
        }
        const axios = require('axios');
        await axios.post(webhook.url, { event, data });
    }
}


class NotificationClient {
    private apiUrl: string;
    private apiKey: string;

    constructor(apiUrl: string, apiKey: string) {
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
    }

    // VULN: SSRF via apiUrl
    async send(payload: NotificationPayload): Promise<any> {
        const axios = require('axios');
        const response = await axios.post(this.apiUrl + '/notifications', payload, {
            headers: { 'Authorization': 'Bearer ' + this.apiKey },
        });
        return response.data;
    }

    async sendBatch(payloads: NotificationPayload[]): Promise<any[]> {
        const results: any[] = [];
        for (const payload of payloads) {
            const result = await this.send(payload);
            results.push(result);
        }
        return results;
    }
}


class FileStorageService {
    private basePath: string;

    constructor(basePath: string) {
        this.basePath = basePath;
    }

    // VULN: Path traversal
    async readFile(filename: string): Promise<string> {
        const filepath = path.join(this.basePath, filename);
        return fs.readFileSync(filepath, 'utf-8');
    }

    // Safe version
    async readFileSafe(filename: string): Promise<string> {
        const safeName = path.basename(filename);
        const filepath = path.join(this.basePath, safeName);
        const resolved = path.resolve(filepath);
        if (!resolved.startsWith(path.resolve(this.basePath))) {
            throw new Error('Path traversal detected');
        }
        return fs.readFileSync(filepath, 'utf-8');
    }

    async writeFile(filename: string, content: string): Promise<void> {
        const safeName = path.basename(filename);
        const filepath = path.join(this.basePath, safeName);
        fs.writeFileSync(filepath, content, 'utf-8');
    }

    async deleteFile(filename: string): Promise<void> {
        const safeName = path.basename(filename);
        const filepath = path.join(this.basePath, safeName);
        fs.unlinkSync(filepath);
    }

    async listFiles(): Promise<string[]> {
        return fs.readdirSync(this.basePath);
    }
}


class ExternalAPIClient {
    private baseUrl: string;
    private timeout: number;

    constructor(baseUrl: string, timeout: number = 5000) {
        this.baseUrl = baseUrl;
        this.timeout = timeout;
    }

    // VULN: SSRF
    async fetch(endpoint: string, params: Record<string, string> = {}): Promise<any> {
        const axios = require('axios');
        const url = this.baseUrl + endpoint;
        const response = await axios.get(url, { params, timeout: this.timeout });
        return response.data;
    }

    async post(endpoint: string, data: any): Promise<any> {
        const axios = require('axios');
        const url = this.baseUrl + endpoint;
        const response = await axios.post(url, data, { timeout: this.timeout });
        return response.data;
    }
}


class CacheService {
    private cache: Map<string, { value: any; expiry: number }>;

    constructor() {
        this.cache = new Map();
    }

    get(key: string): any | null {
        const entry = this.cache.get(key);
        if (!entry) return null;
        if (Date.now() > entry.expiry) {
            this.cache.delete(key);
            return null;
        }
        return entry.value;
    }

    set(key: string, value: any, ttlMs: number = 60000): void {
        this.cache.set(key, { value, expiry: Date.now() + ttlMs });
    }

    delete(key: string): void {
        this.cache.delete(key);
    }

    clear(): void {
        this.cache.clear();
    }
}


export { WebhookManager, NotificationClient, FileStorageService, ExternalAPIClient, CacheService };
