/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
import { execSync } from "child_process";
import * as fs from "fs";

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

function branchKillBothPaths(userInput: string): void {
    // [NO FLOW EXPECTED] Both branches sanitize
    let cmd: string;
    if (userInput.length > 100) {
        cmd = "default_command";
    } else {
        cmd = "safe_fallback";
    }
    execSync(cmd);
}

function branchKillOnePath(userInput: string): void {
    // [FLOW EXPECTED] Only one branch kills taint
    let cmd = userInput;
    if (cmd.length > 100) {
        cmd = "truncated";
    }
    execSync(cmd);
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

function sanitize(value: string): string {
    return value.replace(/['";\-\-]/g, "");
}

function wrapSanitize(value: string): string {
    return sanitize(value);
}

function interproceduralKillDirect(userInput: string): void {
    // [NO FLOW EXPECTED]
    const clean = sanitize(userInput);
    execSync(`echo ${clean}`);
}

function interproceduralKillTwoLevels(userInput: string): void {
    // [NO FLOW EXPECTED]
    const clean = wrapSanitize(userInput);
    execSync(`echo ${clean}`);
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

interface CommandConfig {
    command: string;
    label: string;
}

function fieldSensitiveTainted(userInput: string): void {
    // [FLOW EXPECTED] Tainted field flows to sink
    const cfg: CommandConfig = { command: userInput, label: "safe" };
    execSync(cfg.command);
}

function fieldSensitiveSafe(userInput: string): void {
    // [NO FLOW EXPECTED] Only safe field used
    const cfg: CommandConfig = { command: userInput, label: "safe" };
    execSync(cfg.label);
}


// ---------------------------------------------------------------------------
// 4. EXCEPTION CHAIN TAINT
// ---------------------------------------------------------------------------

function exceptionTaint(userInput: string): void {
    // [FLOW EXPECTED] Taint flows through exception
    try {
        throw new Error(`Invalid: ${userInput}`);
    } catch (e: any) {
        execSync(e.message);
    }
}


// ---------------------------------------------------------------------------
// 5. MULTI-RETURN PRECISION (destructuring)
// ---------------------------------------------------------------------------

function fetchData(source: string): [string, string | null] {
    return [source, null];
}

function multiReturnTainted(userInput: string): void {
    // [FLOW EXPECTED] Position 0 carries taint
    const [data, err] = fetchData(userInput);
    execSync(`echo ${data}`);
}

function multiReturnSafe(userInput: string): void {
    // [NO FLOW EXPECTED] Position 1 is null
    const [data, err] = fetchData(userInput);
    if (err) execSync(`echo ${err}`);
}


// ---------------------------------------------------------------------------
// 6. TYPE-TRACKED CALL RESOLUTION
// ---------------------------------------------------------------------------

interface Executor {
    execute(cmd: string): void;
}

class SafeExecutor implements Executor {
    execute(cmd: string): void {
        console.log(`Would execute: ${cmd}`);
    }
}

class UnsafeExecutor implements Executor {
    execute(cmd: string): void {
        execSync(cmd);
    }
}

function typeTrackedUnsafe(userInput: string): void {
    // [FLOW EXPECTED]
    const executor: Executor = new UnsafeExecutor();
    executor.execute(userInput);
}

function typeTrackedSafe(userInput: string): void {
    // [NO FLOW EXPECTED]
    const executor: Executor = new SafeExecutor();
    executor.execute(userInput);
}


// ---------------------------------------------------------------------------
// 7. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

export function handleWebhook(payload: string, signature: string): void {
    // [FLOW EXPECTED] External entry point
    execSync(`process ${payload}`);
}


// ---------------------------------------------------------------------------
// 8. GENERIC TYPE TAINT PROPAGATION
// ---------------------------------------------------------------------------

function transform<T>(value: T, fn: (v: T) => string): string {
    return fn(value);
}

function genericTaint(userInput: string): void {
    // [FLOW EXPECTED] Taint flows through generic transform
    const result = transform(userInput, (v) => v.toUpperCase());
    execSync(result);
}


// ---------------------------------------------------------------------------
// 9. CROSS-METHOD CLASS FIELD TAINT
// ---------------------------------------------------------------------------

class Pipeline {
    private data: string = "";

    ingest(raw: string): void {
        this.data = raw;
    }

    process(): void {
        execSync(this.data);
    }
}

function crossMethodFieldTaint(userInput: string): void {
    // [FLOW EXPECTED] Taint flows through class field
    const p = new Pipeline();
    p.ingest(userInput);
    p.process();
}


// ---------------------------------------------------------------------------
// 10. ASYNC/AWAIT TAINT PROPAGATION
// ---------------------------------------------------------------------------

async function fetchRemote(url: string): Promise<string> {
    return url; // simulated fetch
}

async function asyncTaint(userInput: string): Promise<void> {
    // [FLOW EXPECTED] Taint survives await
    const data = await fetchRemote(userInput);
    execSync(data);
}
