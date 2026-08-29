const express = require('express');
const { exec } = require('child_process');
const EventEmitter = require('events');
const db = require('./db');
const fs = require('fs');

const app = express();
const bus = new EventEmitter();


// ---------------------------------------------------------------------------
// 1. Promise .then() chain
//    Source: req.query.cmd -> .then(transform) -> .then(build) -> exec()
// ---------------------------------------------------------------------------

function transformInput(raw) {
    return raw.trim().toLowerCase();
}

function buildCommand(fragment) {
    return 'ping -c 1 ' + fragment;
}

// VULN: Command injection via Promise .then() chain — req.query.cmd -> transformInput -> buildCommand -> exec
app.get('/api/ping', (req, res) => {
    const host = req.query.cmd;
    Promise.resolve(host)
        .then(transformInput)
        .then(buildCommand)
        .then(cmd => {
            exec(cmd, (err, stdout) => {
                res.json({ output: stdout });
            });
        });
});


// ---------------------------------------------------------------------------
// 2. async/await + destructuring
//    Source: req.body -> destructure {host, port} -> template literal -> exec()
// ---------------------------------------------------------------------------

async function runHealthCheck(host, port) {
    const target = `${host}:${port}`;
    const command = 'curl -s http://' + target + '/healthz';
    return new Promise((resolve, reject) => {
        exec(command, (err, stdout) => {
            if (err) reject(err);
            else resolve(stdout);
        });
    });
}

// VULN: Command injection via async/await + destructuring — req.body.{host,port} -> runHealthCheck -> exec
app.post('/api/healthcheck', async (req, res) => {
    const { host, port } = req.body;
    const result = await runHealthCheck(host, port);
    res.json({ status: result });
});


// ---------------------------------------------------------------------------
// 3. Optional chaining (?.)
//    Source: req.body.config?.database?.host -> SQL connection string -> db.query()
// ---------------------------------------------------------------------------

function buildConnectionQuery(cfg) {
    const host = cfg?.database?.host;
    const sql = "SELECT 1 FROM dual -- connected to " + host;
    return sql;
}

// VULN: SQL injection via optional chaining — req.body.config?.database?.host -> buildConnectionQuery -> db.query
app.post('/api/db/test', async (req, res) => {
    const cfg = req.body.config;
    const query = buildConnectionQuery(cfg);
    const result = await db.query(query);
    res.json({ connected: true, result });
});


// ---------------------------------------------------------------------------
// 4. Nullish coalescing (??)
//    Source: req.query.sort -> ?? 'name' (but attacker supplies value) -> SQL ORDER BY
// ---------------------------------------------------------------------------

function buildSortedQuery(sortCol, table) {
    const column = sortCol ?? 'name';
    const sql = "SELECT * FROM " + table + " ORDER BY " + column;
    return sql;
}

// VULN: SQL injection via nullish coalescing — req.query.sort ?? default still uses attacker value -> db.query
app.get('/api/users', async (req, res) => {
    const sortCol = req.query.sort;
    const sql = buildSortedQuery(sortCol, 'users');
    const rows = await db.query(sql);
    res.json({ users: rows });
});


// ---------------------------------------------------------------------------
// 5. Spread/rest operators
//    Source: req.body -> spread into options -> command builder -> exec()
// ---------------------------------------------------------------------------

function mergeOptions(defaults, ...overrides) {
    const merged = { ...defaults };
    for (const override of overrides) {
        Object.assign(merged, override);
    }
    return merged;
}

function runExport(options) {
    const cmd = 'exporter --host ' + options.host + ' --format ' + options.format;
    return new Promise((resolve, reject) => {
        exec(cmd, (err, stdout) => {
            if (err) reject(err);
            else resolve(stdout);
        });
    });
}

// VULN: Command injection via spread/rest — req.body spread into merged options -> runExport -> exec
app.post('/api/export', async (req, res) => {
    const userOpts = req.body;
    const defaults = { host: 'localhost', format: 'csv' };
    const finalOpts = mergeOptions(defaults, userOpts);
    const output = await runExport(finalOpts);
    res.json({ output });
});


// ---------------------------------------------------------------------------
// 6. Template literal chain
//    Source: req.params.table -> template literal interpolation chain -> db.query()
// ---------------------------------------------------------------------------

function buildWhereClause(filters) {
    return Object.entries(filters)
        .map(([k, v]) => `${k} = '${v}'`)
        .join(' AND ');
}

function buildSelectQuery(table, where) {
    return `SELECT * FROM ${table} WHERE ${where}`;
}

// VULN: SQL injection via template literal chain — req.params.table + req.query filters -> template interpolation -> db.query
app.get('/api/data/:table', async (req, res) => {
    const table = req.params.table;
    const where = buildWhereClause(req.query);
    const sql = buildSelectQuery(table, where);
    const rows = await db.query(sql);
    res.json({ rows });
});


// ---------------------------------------------------------------------------
// 7. Array destructuring
//    Source: req.body.targets -> array destructure [primary, ...rest] -> exec each
// ---------------------------------------------------------------------------

function scanTarget(target) {
    const cmd = 'nmap -sV ' + target;
    return new Promise((resolve, reject) => {
        exec(cmd, (err, stdout) => {
            if (err) reject(err);
            else resolve(stdout);
        });
    });
}

// VULN: Command injection via array destructuring — req.body.targets destructured -> scanTarget -> exec
app.post('/api/scan', async (req, res) => {
    const [primary, ...secondary] = req.body.targets;
    const mainResult = await scanTarget(primary);
    const secondaryResults = [];
    for (const target of secondary) {
        const r = await scanTarget(target);
        secondaryResults.push(r);
    }
    res.json({ primary: mainResult, secondary: secondaryResults });
});


// ---------------------------------------------------------------------------
// 8. Callback registration (EventEmitter pattern)
//    Source: req.body -> emit 'process' event -> listener calls exec()
// ---------------------------------------------------------------------------

bus.on('process', (data) => {
    const cmd = 'process-data --input ' + data.filename;
    exec(cmd, (err, stdout) => {
        if (err) console.error('process failed:', err);
    });
});

// VULN: Command injection via EventEmitter — req.body.filename -> bus.emit('process') -> listener -> exec
app.post('/api/process', (req, res) => {
    const payload = req.body;
    bus.emit('process', payload);
    res.json({ queued: true });
});


// ---------------------------------------------------------------------------
// 9. Generator function
//    Source: req.body.queries -> generator yields each -> db.query() consumes
// ---------------------------------------------------------------------------

function* queryGenerator(queries) {
    for (const q of queries) {
        yield "SELECT * FROM logs WHERE message LIKE '%" + q + "%'";
    }
}

// VULN: SQL injection via generator — req.body.queries -> generator yields SQL strings -> db.query
app.post('/api/logs/search', async (req, res) => {
    const queries = req.body.queries;
    const results = [];
    for (const sql of queryGenerator(queries)) {
        const rows = await db.query(sql);
        results.push(rows);
    }
    res.json({ results });
});


// ---------------------------------------------------------------------------
// 10. reduce -> SQL
//     Source: req.body.filters -> Array.reduce builds WHERE clause -> db.query()
// ---------------------------------------------------------------------------

function buildFilterQuery(table, filters) {
    const whereParts = filters.reduce((acc, filter) => {
        acc.push(filter.field + " = '" + filter.value + "'");
        return acc;
    }, []);
    const whereClause = whereParts.join(' OR ');
    return "SELECT * FROM " + table + " WHERE " + whereClause;
}

// VULN: SQL injection via reduce — req.body.filters reduced into WHERE clause -> db.query
app.post('/api/query', async (req, res) => {
    const filters = req.body.filters;
    const table = req.body.table;
    const sql = buildFilterQuery(table, filters);
    const rows = await db.query(sql);
    res.json({ rows });
});


// ---------------------------------------------------------------------------
// 11. Dynamic property access
//     Source: req.query.key -> bracket notation lookup on config -> eval()
// ---------------------------------------------------------------------------

const dynamicHandlers = {
    transform: (v) => v.toUpperCase(),
    validate: (v) => v.length > 0,
    execute: (v) => eval(v),
};

// VULN: Code injection via dynamic property access — req.query.key selects handler, req.query.value passed to eval
app.get('/api/dynamic', (req, res) => {
    const key = req.query.key;
    const value = req.query.value;
    const handler = dynamicHandlers[key];
    if (handler) {
        const result = handler(value);
        res.json({ result });
    } else {
        res.status(400).json({ error: 'Unknown handler' });
    }
});


// ---------------------------------------------------------------------------
// 12. Chained class methods (builder pattern) -> file write
//     Source: req.body -> builder chain -> fs.writeFileSync()
// ---------------------------------------------------------------------------

class ReportBuilder {
    constructor() {
        this.parts = [];
        this.outputPath = '/tmp/report.txt';
    }

    setTitle(title) {
        this.parts.push('# ' + title);
        return this;
    }

    addSection(heading, content) {
        this.parts.push('## ' + heading + '\n' + content);
        return this;
    }

    setOutputPath(p) {
        this.outputPath = p;
        return this;
    }

    build() {
        const report = this.parts.join('\n\n');
        fs.writeFileSync(this.outputPath, report);
        return this.outputPath;
    }
}

// VULN: Path traversal via builder pattern — req.body.path -> setOutputPath -> build -> fs.writeFileSync
app.post('/api/report/generate', (req, res) => {
    const { title, sections, path: outputPath } = req.body;
    const builder = new ReportBuilder();
    builder.setTitle(title);
    for (const section of sections) {
        builder.addSection(section.heading, section.content);
    }
    builder.setOutputPath(outputPath);
    const filePath = builder.build();
    res.json({ generated: filePath });
});


// ---------------------------------------------------------------------------
// 13. Ternary + string concatenation -> XSS
//     Source: req.query.name -> ternary selection -> HTML response
// ---------------------------------------------------------------------------

function renderGreeting(name, isAdmin) {
    const role = isAdmin ? 'Administrator' : 'User';
    const html = '<div class="greeting"><h1>Welcome, '
        + name + '</h1><span class="role">' + role + '</span></div>';
    return html;
}

// VULN: XSS via ternary + string concat — req.query.name -> renderGreeting -> res.send (unsanitized HTML)
app.get('/api/greet', (req, res) => {
    const name = req.query.name;
    const isAdmin = req.query.admin === 'true';
    const html = renderGreeting(name, isAdmin);
    res.send(html);
});


module.exports = {
    app,
    bus,
    ReportBuilder,
    transformInput,
    buildCommand,
    runHealthCheck,
    buildConnectionQuery,
    buildSortedQuery,
    mergeOptions,
    runExport,
    buildWhereClause,
    buildSelectQuery,
    scanTarget,
    queryGenerator,
    buildFilterQuery,
    renderGreeting,
};

// ============================================================
// ADDITIONAL PATTERNS - Try/catch flow, async generators, Proxy
// ============================================================

// Try/catch/finally taint flow
function tryCatchFlow(input) {
    try {
        const result = JSON.parse(input);
        exec(result.cmd);  // taint through try body
    } catch (error) {
        // Error message may contain tainted data
        console.error(`Parse failed: ${error.message}`);
    } finally {
        cleanup(input);
    }
}

// Async generator with taint
async function* asyncGeneratorFlow(urls) {
    for (const url of urls) {
        const response = await fetch(url);
        const data = await response.text();
        yield data;  // taint flows through async generator
    }
}

// Proxy handler intercepting tainted data
function createProxy(target) {
    return new Proxy(target, {
        get(obj, prop) {
            return obj[prop];  // taint through proxy get trap
        },
        set(obj, prop, value) {
            obj[prop] = value;  // taint through proxy set trap
            return true;
        }
    });
}

// WeakRef/FinalizationRegistry flow
function weakRefFlow(input) {
    const ref = new WeakRef({ cmd: input });
    const deref = ref.deref();
    if (deref) {
        exec(deref.cmd);  // taint through WeakRef
    }
}

// Nullish coalescing chain
function nullishFlow(input) {
    const cmd = input?.command ?? input?.cmd ?? "default";
    exec(cmd);  // taint through nullish chain
}

// Symbol-keyed property access
const CMD_KEY = Symbol('command');
function symbolFlow(obj) {
    obj[CMD_KEY] = 'ls';
    exec(obj[CMD_KEY]);
}
