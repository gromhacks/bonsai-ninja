import { Request, Response } from 'express';
import * as fs from 'fs';
import { execSync } from 'child_process';

// ---------------------------------------------------------------------------
// Types and interfaces
// ---------------------------------------------------------------------------

interface DatabaseClient {
    query(sql: string, params?: any[]): Promise<any[]>;
}

interface Identifiable {
    id: string;
}

interface HasPayload {
    payload: string;
}

// Discriminated union for event routing
type AppEvent =
    | { kind: 'user_command'; command: string }
    | { kind: 'file_upload'; filename: string; content: string }
    | { kind: 'query_request'; sql: string }
    | { kind: 'eval_script'; code: string };

// Enum for report format routing
enum ReportFormat {
    SQL = 'sql',
    Shell = 'shell',
    Template = 'template',
    File = 'file',
}

// Interface for dispatch pattern
interface DataProcessor {
    process(data: string): Promise<string>;
}

// Mapped type alias
type FieldRecord = Record<string, string>;

// ---------------------------------------------------------------------------
// VULN 1: Generic function with type parameter flowing taint
// Chain: req.query.filter -> extractField<T>() -> db.query(unsanitized)
// The generic preserves the tainted string through the type parameter.
// ---------------------------------------------------------------------------

function extractField<T extends Identifiable & HasPayload>(
    obj: T,
    db: DatabaseClient
): Promise<any[]> {
    const value: string = obj.payload;
    const sql: string = "SELECT * FROM items WHERE data = '" + value + "'";
    return db.query(sql);
}

async function handleGenericRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const item: Identifiable & HasPayload = {
        id: req.query.id as string,
        payload: req.query.filter as string,
    };
    const results = await extractField(item, db);
    res.json(results);
}

// ---------------------------------------------------------------------------
// VULN 2: Type guard narrowing -- taint survives the `is` check
// Chain: req.body.input -> isStringInput() narrows type -> db.query(tainted)
// The type guard confirms the shape but does NOT sanitize the value.
// ---------------------------------------------------------------------------

interface StringInput {
    kind: 'string';
    value: string;
}

interface NumberInput {
    kind: 'number';
    value: number;
}

type MixedInput = StringInput | NumberInput;

function isStringInput(input: MixedInput): input is StringInput {
    return input.kind === 'string';
}

async function handleTypeGuardRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const input: MixedInput = req.body.input;
    if (isStringInput(input)) {
        // Type guard confirms shape, but value is still user-controlled
        const sql: string = "SELECT * FROM data WHERE col = '" + input.value + "'";
        const rows = await db.query(sql);
        res.json(rows);
    } else {
        res.json({ value: input.value });
    }
}

// ---------------------------------------------------------------------------
// VULN 3: Discriminated union switch routing tainted data to sinks
// Chain: req.body -> AppEvent discriminated union -> switch(kind) -> multiple sinks
// Each branch of the switch sends tainted data to a different dangerous sink.
// ---------------------------------------------------------------------------

async function dispatchEvent(event: AppEvent, db: DatabaseClient): Promise<string> {
    switch (event.kind) {
        case 'user_command': {
            // VULN 3a: command injection
            const output: string = execSync('run-task ' + event.command).toString();
            return output;
        }
        case 'file_upload': {
            // VULN 3b: path traversal + arbitrary file write
            fs.writeFileSync('/uploads/' + event.filename, event.content);
            return 'uploaded';
        }
        case 'query_request': {
            // VULN 3c: SQL injection
            const rows = await db.query("SELECT * FROM logs WHERE " + event.sql);
            return JSON.stringify(rows);
        }
        case 'eval_script': {
            // VULN 3d: code injection
            const result: any = eval(event.code);
            return String(result);
        }
    }
}

async function handleEventRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const event: AppEvent = req.body as AppEvent;
    const result: string = await dispatchEvent(event, db);
    res.send(result);
}

// ---------------------------------------------------------------------------
// VULN 4: Async generator yielding tainted values to a sink
// Chain: req.query.terms -> streamSearch() async generator -> db.query(tainted)
// The async generator yields tainted SQL results without sanitization.
// ---------------------------------------------------------------------------

async function* streamSearch(
    terms: string[],
    db: DatabaseClient
): AsyncGenerator<any[], void, unknown> {
    for (const term of terms) {
        const sql: string = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
        const batch: any[] = await db.query(sql);
        yield batch;
    }
}

async function handleStreamRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const terms: string[] = (req.query.terms as string).split(',');
    const allResults: any[] = [];
    for await (const batch of streamSearch(terms, db)) {
        allResults.push(...batch);
    }
    res.json(allResults);
}

// ---------------------------------------------------------------------------
// VULN 5: Interface dispatch -- taint flows through interface method
// Chain: req.body.data -> SqlProcessor.process() -> db.query(tainted)
// The interface type hides the concrete implementation that sinks to SQL.
// ---------------------------------------------------------------------------

class SqlProcessor implements DataProcessor {
    private db: DatabaseClient;

    constructor(db: DatabaseClient) {
        this.db = db;
    }

    async process(data: string): Promise<string> {
        const sql: string = "INSERT INTO audit_log (entry) VALUES ('" + data + "')";
        await this.db.query(sql);
        return 'logged';
    }
}

async function handleInterfaceRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const processor: DataProcessor = new SqlProcessor(db);
    const input: string = req.body.data;
    const result: string = await processor.process(input);
    res.json({ status: result });
}

// ---------------------------------------------------------------------------
// VULN 6: Mapped type / Record with tainted values
// Chain: req.body.fields (Record) -> buildInsert() -> db.query(tainted)
// Tainted values inside a Record<string,string> flow into SQL concatenation.
// ---------------------------------------------------------------------------

function buildInsert(table: string, fields: FieldRecord): string {
    const columns: string = Object.keys(fields).join(', ');
    const values: string = Object.values(fields).map(v => "'" + v + "'").join(', ');
    return `INSERT INTO ${table} (${columns}) VALUES (${values})`;
}

async function handleMappedTypeRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const fields: FieldRecord = req.body.fields;
    const sql: string = buildInsert('user_profiles', fields);
    await db.query(sql);
    res.json({ status: 'inserted' });
}

// ---------------------------------------------------------------------------
// VULN 7: Decorator on method -- taint flows through decorated method
// Chain: req.params.id -> AdminController.deleteItem() -> exec(tainted)
// The decorator wraps the method but does not sanitize arguments.
// ---------------------------------------------------------------------------

function logExecution(target: any, key: string, descriptor: PropertyDescriptor): PropertyDescriptor {
    const original = descriptor.value;
    descriptor.value = function (...args: any[]) {
        console.log(`Calling ${key} with`, args);
        return original.apply(this, args);
    };
    return descriptor;
}

class AdminController {
    @logExecution
    runCleanup(targetPath: string): string {
        // VULN: command injection -- decorator does not sanitize
        const output: string = execSync('rm -rf ' + targetPath).toString();
        return output;
    }
}

async function handleDecoratorRoute(req: Request, res: Response): Promise<void> {
    const controller = new AdminController();
    const targetPath: string = req.params.path;
    const result: string = controller.runCleanup(targetPath);
    res.send(result);
}

// ---------------------------------------------------------------------------
// VULN 8: Enum switch routing taint to different sinks
// Chain: req.body.format (enum) + req.body.content -> switch -> multiple sinks
// The enum selects which dangerous sink receives the tainted content.
// ---------------------------------------------------------------------------

async function generateReport(
    format: ReportFormat,
    content: string,
    db: DatabaseClient
): Promise<string> {
    switch (format) {
        case ReportFormat.SQL: {
            const sql: string = "INSERT INTO reports (body) VALUES ('" + content + "')";
            await db.query(sql);
            return 'stored in db';
        }
        case ReportFormat.Shell: {
            const output: string = execSync('echo ' + content + ' | format-report').toString();
            return output;
        }
        case ReportFormat.Template: {
            const result: any = eval('`' + content + '`');
            return String(result);
        }
        case ReportFormat.File: {
            fs.writeFileSync('/tmp/report_' + Date.now() + '.txt', content);
            return 'written to file';
        }
    }
}

async function handleEnumRoute(req: Request, res: Response, db: DatabaseClient): Promise<void> {
    const format: ReportFormat = req.body.format as ReportFormat;
    const content: string = req.body.content;
    const result: string = await generateReport(format, content, db);
    res.json({ result });
}

// ---------------------------------------------------------------------------
// VULN 9: Assertion function -- asserts x is T -- taint survives assertion
// Chain: req.body.config -> assertIsConfig() -> exec(tainted field)
// The assertion function validates structure but the string value is still tainted.
// ---------------------------------------------------------------------------

interface ServerConfig {
    host: string;
    command: string;
    port: number;
}

function assertIsConfig(val: unknown): asserts val is ServerConfig {
    if (typeof val !== 'object' || val === null) {
        throw new Error('Not an object');
    }
    const obj = val as Record<string, unknown>;
    if (typeof obj.host !== 'string' || typeof obj.command !== 'string' || typeof obj.port !== 'number') {
        throw new Error('Invalid config shape');
    }
}

async function handleAssertionRoute(req: Request, res: Response): Promise<void> {
    const raw: unknown = req.body.config;
    assertIsConfig(raw);
    // After assertion, TypeScript knows raw is ServerConfig, but values are still user-controlled
    const output: string = execSync(raw.command).toString();
    res.json({ host: raw.host, output });
}

// ---------------------------------------------------------------------------
// VULN 10: Nullish coalesce assignment (??=) with tainted fallback
// Chain: req.query.snippet -> cachedSnippets[key] ??= taintedValue -> eval(cached)
// The ??= operator assigns the tainted value when the cache is empty,
// then the cached (tainted) value is passed to eval.
// ---------------------------------------------------------------------------

const cachedSnippets: Record<string, string> = {};

async function handleNullishCoalesceRoute(req: Request, res: Response): Promise<void> {
    const key: string = req.query.key as string;
    const snippet: string = req.query.snippet as string;
    cachedSnippets[key] ??= snippet;
    const result: any = eval(cachedSnippets[key]);
    res.json({ result });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export {
    extractField,
    handleGenericRoute,
    isStringInput,
    handleTypeGuardRoute,
    dispatchEvent,
    handleEventRoute,
    streamSearch,
    handleStreamRoute,
    SqlProcessor,
    handleInterfaceRoute,
    buildInsert,
    handleMappedTypeRoute,
    AdminController,
    handleDecoratorRoute,
    generateReport,
    handleEnumRoute,
    assertIsConfig,
    handleAssertionRoute,
    handleNullishCoalesceRoute,
    ReportFormat,
    AppEvent,
    DataProcessor,
    FieldRecord,
    ServerConfig,
};

// Optional chaining flow
function optionalChainFlow(req?: { query?: { cmd?: string } }): void {
    const cmd = req?.query?.cmd;
    if (cmd) {
        exec(cmd);
    }
}
