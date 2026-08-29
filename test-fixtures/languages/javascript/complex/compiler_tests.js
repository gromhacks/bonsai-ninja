/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
const { execSync } = require("child_process");
const fs = require("fs");

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

function branchKillBothPaths(userInput) {
    // [NO FLOW EXPECTED] Both branches sanitize
    let cmd;
    if (userInput.length > 100) {
        cmd = "default_command";
    } else {
        cmd = "safe_fallback";
    }
    execSync(cmd); // safe: both paths overwrite cmd
}

function branchKillOnePath(userInput) {
    // [FLOW EXPECTED] Only one branch kills taint
    let cmd = userInput;
    if (cmd.length > 100) {
        cmd = "truncated";
    }
    // else: cmd still holds userInput
    execSync(cmd); // tainted: else path preserves input
}

function branchKillSwitch(userInput) {
    // [FLOW EXPECTED] Switch with default fallthrough
    let query = userInput;
    switch (query.charAt(0)) {
        case "a":
            query = "SELECT * FROM a";
            break;
        case "b":
            query = "SELECT * FROM b";
            break;
        // no default: query keeps userInput for other chars
    }
    execSync(`sqlite3 db.sqlite "${query}"`);
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

function sanitize(value) {
    return value.replace(/['";\-\-]/g, "");
}

function wrapSanitize(value) {
    return sanitize(value);
}

function interproceduralKillDirect(userInput) {
    // [NO FLOW EXPECTED] Sanitizer applied before sink
    const clean = sanitize(userInput);
    execSync(`echo ${clean}`);
}

function interproceduralKillTwoLevels(userInput) {
    // [NO FLOW EXPECTED] Sanitizer 2 levels deep
    const clean = wrapSanitize(userInput);
    execSync(`echo ${clean}`);
}

function interproceduralNoKill(userInput) {
    // [FLOW EXPECTED] No sanitizer
    execSync(`echo ${userInput}`);
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

function fieldSensitiveTainted(userInput) {
    // [FLOW EXPECTED] Tainted field flows to sink
    const cfg = { command: userInput, label: "safe" };
    execSync(cfg.command);
}

function fieldSensitiveSafe(userInput) {
    // [NO FLOW EXPECTED] Only safe field used
    const cfg = { command: userInput, label: "safe" };
    execSync(cfg.label);
}

function fieldSensitiveOverwrite(userInput) {
    // [NO FLOW EXPECTED] Tainted field overwritten
    const cfg = { command: userInput };
    cfg.command = "hardcoded_safe";
    execSync(cfg.command);
}


// ---------------------------------------------------------------------------
// 4. EXCEPTION CHAIN TAINT
// ---------------------------------------------------------------------------

function exceptionTaintInMessage(userInput) {
    // [FLOW EXPECTED] Taint flows through exception
    try {
        throw new Error(`Invalid: ${userInput}`);
    } catch (e) {
        execSync(e.message); // tainted
    }
}


// ---------------------------------------------------------------------------
// 5. CONTAINER ELEMENT PRECISION
// ---------------------------------------------------------------------------

function containerElementOverwrite(userInput) {
    // [NO FLOW EXPECTED] Element overwritten
    const arr = [userInput, "ls", "pwd"];
    arr[0] = "safe_command";
    execSync(arr[0]);
}

function containerAppendTainted(userInput) {
    // [FLOW EXPECTED] Tainted element pushed
    const parts = [];
    parts.push(userInput);
    execSync(parts.join(" "));
}


// ---------------------------------------------------------------------------
// 6. MULTI-RETURN PRECISION (destructuring)
// ---------------------------------------------------------------------------

function fetchData(source) {
    return [source, null]; // [data, error]
}

function multiReturnTainted(userInput) {
    // [FLOW EXPECTED] Position 0 carries taint
    const [data, err] = fetchData(userInput);
    execSync(`echo ${data}`);
}

function multiReturnSafe(userInput) {
    // [NO FLOW EXPECTED] Position 1 is null literal
    const [data, err] = fetchData(userInput);
    execSync(`echo ${err}`);
}


// ---------------------------------------------------------------------------
// 7. TYPE-TRACKED CALL RESOLUTION
// ---------------------------------------------------------------------------

class SafeExecutor {
    execute(cmd) {
        console.log(`Would execute: ${cmd}`);
    }
}

class UnsafeExecutor {
    execute(cmd) {
        execSync(cmd);
    }
}

function typeTrackedUnsafe(userInput) {
    // [FLOW EXPECTED] UnsafeExecutor.execute reaches execSync
    const executor = new UnsafeExecutor();
    executor.execute(userInput);
}

function typeTrackedSafe(userInput) {
    // [NO FLOW EXPECTED] SafeExecutor.execute does not reach execSync
    const executor = new SafeExecutor();
    executor.execute(userInput);
}


// ---------------------------------------------------------------------------
// 8. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

function handleWebhook(payload, signature) {
    // [FLOW EXPECTED] External entry point params as taint sources
    execSync(`process ${payload}`);
}

function handleApiRequest(query) {
    // [FLOW EXPECTED] External entry point param flows to sink
    execSync(`sqlite3 db.sqlite "SELECT * FROM data WHERE q = '${query}'"`);
}


// ---------------------------------------------------------------------------
// 9. CALLBACK / HOF TAINT PROPAGATION
// ---------------------------------------------------------------------------

function processWithCallback(userInput, callback) {
    // [FLOW EXPECTED] Taint flows through callback
    callback(userInput);
}

function hofChain(userInput) {
    // [FLOW EXPECTED] Taint flows through HOF
    const items = [userInput];
    const result = items.map(x => x.trim()).join(" ");
    execSync(result);
}


// ---------------------------------------------------------------------------
// 10. CROSS-METHOD CLASS FIELD TAINT
// ---------------------------------------------------------------------------

class Pipeline {
    constructor() {
        this.data = "";
    }

    ingest(raw) {
        this.data = raw;
    }

    process() {
        execSync(this.data); // tainted if ingest() was called with tainted input
    }
}

function crossMethodFieldTaint(userInput) {
    // [FLOW EXPECTED] Taint flows through class field
    const p = new Pipeline();
    p.ingest(userInput);
    p.process();
}

module.exports = {
    branchKillBothPaths, branchKillOnePath, branchKillSwitch,
    interproceduralKillDirect, interproceduralKillTwoLevels, interproceduralNoKill,
    fieldSensitiveTainted, fieldSensitiveSafe, fieldSensitiveOverwrite,
    exceptionTaintInMessage,
    containerElementOverwrite, containerAppendTainted,
    multiReturnTainted, multiReturnSafe,
    typeTrackedUnsafe, typeTrackedSafe,
    handleWebhook, handleApiRequest,
    processWithCallback, hofChain,
    crossMethodFieldTaint,
};
