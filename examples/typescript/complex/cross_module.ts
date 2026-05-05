import { Request, Response } from 'express';
import { UserService, CommentService, AnalyticsService } from './services';
import { createSchema, QueryResolvers, AdminResolvers } from './schema';
import { UserRepository, PostRepository, QueryBuilder } from './repository';
import { WebhookManager, FileStorageService, ExternalAPIClient } from './integrations';
import { sanitizeHtml, verifyJWT, parseAuthToken } from './middleware';

// ---------------------------------------------------------------------------
// Chain A: 10+ hops across 4 files -- deep interprocedural SQL injection
//
// Full chain (12 hops):
//   1. req.query.search           (cross_module.ts - handleDeepSearch)
//   2. -> extractSearchTerm()     (cross_module.ts)
//   3. -> normalizeQuery()        (cross_module.ts)
//   4. -> buildSearchFilter()     (cross_module.ts)
//   5. -> QueryBuilder.where()    (repository.ts - accepts raw string)
//   6. -> QueryBuilder.build()    (repository.ts - concatenates into SQL)
//   7. -> executeBuiltQuery()     (cross_module.ts)
//   8. -> logQueryToAnalytics()   (cross_module.ts)
//   9. -> AnalyticsService.customQuery()  (services.ts - second sink)
//  10. -> formatResults()         (cross_module.ts)
//  11. -> enrichWithUserData()    (cross_module.ts)
//  12. -> UserRepository.search() (repository.ts - third sink via user lookup)
//
// The tainted search term flows through 6 helper functions, into
// QueryBuilder (repository.ts), then the result triggers further
// queries in AnalyticsService (services.ts) and UserRepository (repository.ts).
// ---------------------------------------------------------------------------

function extractSearchTerm(req: Request): string {
    const raw: string = req.query.search as string;
    return raw.trim();
}

function normalizeQuery(term: string): string {
    return term.toLowerCase().replace(/\s+/g, ' ');
}

function buildSearchFilter(normalized: string): string {
    return "title LIKE '%" + normalized + "%' OR content LIKE '%" + normalized + "%'";
}

async function executeBuiltQuery(filter: string, db: any): Promise<any[]> {
    const qb = new QueryBuilder('posts');
    qb.where(filter);
    const sql: string = qb.build();
    return db.query(sql);
}

async function logQueryToAnalytics(
    searchTerm: string,
    analytics: AnalyticsService
): Promise<void> {
    // Passes tainted term as a raw analytics query -- second sink
    await analytics.customQuery("event = 'search' AND metadata LIKE '%" + searchTerm + "%'");
}

function formatResults(rows: any[]): string[] {
    return rows.map((r: any) => r.author_name as string);
}

async function enrichWithUserData(
    authorNames: string[],
    userRepo: UserRepository
): Promise<any[]> {
    const allUsers: any[] = [];
    for (const name of authorNames) {
        // Each author name came from tainted search results -- third sink
        const users = await userRepo.search(name);
        allUsers.push(...users);
    }
    return allUsers;
}

async function handleDeepSearch(req: Request, res: Response, db: any): Promise<void> {
    const userRepo = new UserRepository(db);
    const analytics = new AnalyticsService(db);

    const raw: string = extractSearchTerm(req);
    const normalized: string = normalizeQuery(raw);
    const filter: string = buildSearchFilter(normalized);
    const rows: any[] = await executeBuiltQuery(filter, db);
    await logQueryToAnalytics(normalized, analytics);
    const authorNames: string[] = formatResults(rows);
    const enriched: any[] = await enrichWithUserData(authorNames, userRepo);
    res.json({ posts: rows, authors: enriched });
}

// ---------------------------------------------------------------------------
// Chain B: Module-level variable -- taint stored at module scope
//
// Full chain:
//   1. req.body.template          (cross_module.ts - registerTemplate)
//   2. -> moduleTemplateCache     (cross_module.ts - module-level variable)
//   3. -> renderCachedTemplate()  (cross_module.ts - reads module var)
//   4. -> AdminResolvers.importData() style eval  (eval sink)
//
// A POST route stores a user-controlled template string in a module-level
// variable. A later GET route reads from that variable and passes it
// to eval, creating a stored code injection vulnerability across requests.
// ---------------------------------------------------------------------------

let moduleTemplateCache: string = '';

async function registerTemplate(req: Request, res: Response): Promise<void> {
    const template: string = req.body.template;
    moduleTemplateCache = template;
    res.json({ status: 'registered' });
}

async function renderCachedTemplate(req: Request, res: Response): Promise<void> {
    const stored: string = moduleTemplateCache;
    // VULN: eval on previously stored user input from module-level cache
    const rendered: any = eval('`' + stored + '`');
    res.json({ rendered });
}

// ---------------------------------------------------------------------------
// Chain C: Callback pattern -- taint flows through higher-order function
//
// Full chain:
//   1. req.body.url               (cross_module.ts - handleCallbackFetch)
//   2. -> fetchAndProcess()       (cross_module.ts - accepts callback)
//   3. -> ExternalAPIClient.fetch()  (integrations.ts - SSRF sink)
//   4. -> callback(response)      (cross_module.ts - callback invoked with result)
//   5. -> FileStorageService.writeFile()  (integrations.ts - writes response)
//   6. -> WebhookManager.notify() (integrations.ts - notifies with data)
//
// The user-supplied URL is passed to ExternalAPIClient (integrations.ts),
// and the fetched response flows through a callback into FileStorageService
// (integrations.ts) and WebhookManager (integrations.ts).
// ---------------------------------------------------------------------------

async function fetchAndProcess(
    endpoint: string,
    client: ExternalAPIClient,
    callback: (data: any) => Promise<void>
): Promise<void> {
    // VULN: SSRF -- user-controlled endpoint goes to ExternalAPIClient.fetch
    const response: any = await client.fetch(endpoint);
    await callback(response);
}

async function handleCallbackFetch(req: Request, res: Response): Promise<void> {
    const client = new ExternalAPIClient(req.body.baseUrl);
    const storage = new FileStorageService('/data/fetched');
    const webhooks = new WebhookManager();

    const endpoint: string = req.body.endpoint;

    await fetchAndProcess(endpoint, client, async (data: any) => {
        // Callback writes fetched (potentially malicious) data to file
        await storage.writeFile('fetched_' + Date.now() + '.json', JSON.stringify(data));
        // And notifies via webhook
        await webhooks.notify('data.fetched', data);
    });

    res.json({ status: 'fetched and processed' });
}

// ---------------------------------------------------------------------------
// Chain D: Re-exported wrapper -- thin wrappers re-expose dangerous functions
//
// Full chain:
//   1. req.params.sql             (cross_module.ts - handleWrappedQuery)
//   2. -> runAdminQuery()         (cross_module.ts - wrapper)
//   3. -> AdminResolvers.runQuery()  (schema.ts - SQL injection sink)
//   4. req.body.task              (cross_module.ts - handleWrappedMaintenance)
//   5. -> runMaintenance()        (cross_module.ts - wrapper)
//   6. -> AdminResolvers.runMaintenance()  (schema.ts - command injection sink)
//
// Thin wrapper functions re-export the admin resolvers from schema.ts
// without adding any sanitization, creating a pass-through to the sinks.
// ---------------------------------------------------------------------------

function createAdminFacade(db: any): AdminResolvers {
    return new AdminResolvers(db);
}

async function runAdminQuery(
    sql: string,
    admin: AdminResolvers,
    ctx: any
): Promise<any[]> {
    // Passes through to AdminResolvers.runQuery -- SQL injection
    return admin.runQuery({ sql }, ctx);
}

async function runMaintenance(
    task: string,
    admin: AdminResolvers,
    ctx: any
): Promise<string> {
    // Passes through to AdminResolvers.runMaintenance -- command injection
    return admin.runMaintenance({ task }, ctx);
}

async function handleWrappedQuery(req: Request, res: Response): Promise<void> {
    const db: any = (req as any).db;
    const admin: AdminResolvers = createAdminFacade(db);
    const ctx = { req, res, userId: 'admin', db };

    const userSql: string = req.params.sql;
    const results = await runAdminQuery(userSql, admin, ctx);
    res.json(results);
}

async function handleWrappedMaintenance(req: Request, res: Response): Promise<void> {
    const db: any = (req as any).db;
    const admin: AdminResolvers = createAdminFacade(db);
    const ctx = { req, res, userId: 'admin', db };

    const task: string = req.body.task;
    const output: string = await runMaintenance(task, admin, ctx);
    res.send(output);
}

// ---------------------------------------------------------------------------
// Chain E: Recursive chain -- taint propagated through recursive expansion
//
// Full chain:
//   1. req.body.expression        (cross_module.ts - handleRecursiveEval)
//   2. -> expandMacros()          (cross_module.ts - recursive, calls itself)
//   3. -> expandMacros() [recursive depth N]
//   4. -> CommentService.searchComments()  (services.ts - SQL injection sink)
//
// A user-supplied expression string containing macro references like
// {{lookup:term}} is recursively expanded. Each expansion substitutes
// user-controlled data, and the final expanded string is used as a
// search term in CommentService.searchComments (services.ts), which
// concatenates it into a SQL query.
// ---------------------------------------------------------------------------

async function expandMacros(
    expression: string,
    depth: number,
    db: any
): Promise<string> {
    if (depth > 10) {
        return expression;
    }

    const macroPattern: RegExp = /\{\{lookup:([^}]+)\}\}/g;
    let expanded: string = expression;
    let match: RegExpExecArray | null;

    // Reset regex state
    macroPattern.lastIndex = 0;
    match = macroPattern.exec(expression);

    if (match !== null) {
        const term: string = match[1];
        // Fetch replacement from DB (still tainted)
        const rows: any[] = await db.query(
            "SELECT value FROM macros WHERE key = ?", [term]
        );
        const replacement: string = rows.length > 0 ? rows[0].value : term;
        expanded = expression.replace(match[0], replacement);
        // Recurse to expand any nested macros in the replacement
        return expandMacros(expanded, depth + 1, db);
    }

    return expanded;
}

async function handleRecursiveEval(req: Request, res: Response): Promise<void> {
    const db: any = (req as any).db;
    const commentService = new CommentService(db);

    const expression: string = req.body.expression;
    const expanded: string = await expandMacros(expression, 0, db);
    // VULN: expanded string (derived from user input) goes to SQL injection sink
    const comments: any[] = await commentService.searchComments(expanded);
    res.json({ expanded, comments });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export {
    handleDeepSearch,
    registerTemplate,
    renderCachedTemplate,
    handleCallbackFetch,
    handleWrappedQuery,
    handleWrappedMaintenance,
    handleRecursiveEval,
    extractSearchTerm,
    normalizeQuery,
    buildSearchFilter,
    executeBuiltQuery,
    expandMacros,
    fetchAndProcess,
    runAdminQuery,
    runMaintenance,
    createAdminFacade,
};
