/**
 * Auth decorator patterns for testing decorator flow analysis.
 */

import { execSync } from "child_process";

// --- Decorator definitions ---

function Authenticated(target: any, key: string, desc: PropertyDescriptor) {
    const original = desc.value;
    desc.value = function (...args: any[]) {
        const userId = getSessionUser();
        if (!userId) {
            throw new Error("Unauthorized");
        }
        return original.apply(this, args);
    };
    return desc;
}

function AdminOnly(target: any, key: string, desc: PropertyDescriptor) {
    const original = desc.value;
    desc.value = function (...args: any[]) {
        const user = getCurrentUser();
        if (!user || user.role !== "admin") {
            throw new Error("Forbidden");
        }
        return original.apply(this, args);
    };
    return desc;
}

function RateLimit(maxCalls: number) {
    return function (target: any, key: string, desc: PropertyDescriptor) {
        // VULN: no actual rate limiting
        return desc;
    };
}

// --- Helpers ---

function getSessionUser(): string | null {
    return process.env.USER_ID || null;
}

function getCurrentUser(): { id: string; role: string } | null {
    const uid = process.env.USER_ID;
    if (uid) {
        return { id: uid, role: "user" };
    }
    return null;
}

// --- Controller using auth decorators ---

class UserController {
    @Authenticated
    getProfile(userId: string): string {
        // VULN: SQL injection in authenticated endpoint
        const query = "SELECT * FROM users WHERE id = " + userId;
        return query;
    }

    @Authenticated
    @RateLimit(5)
    changePassword(oldPw: string, newPw: string): string {
        // VULN: weak hash in stacked-decorator endpoint
        const crypto = require("crypto");
        const hash = crypto.createHash("md5").update(newPw).digest("hex");
        return "UPDATE users SET pw = '" + hash + "'";
    }

    @AdminOnly
    deleteUser(targetId: string): string {
        // VULN: SQL injection in admin-only endpoint
        return "DELETE FROM users WHERE id = " + targetId;
    }

    @AdminOnly
    runCommand(cmd: string): string {
        // VULN: command injection in admin-only endpoint
        return execSync(cmd).toString();
    }
}

// --- Entry point ---
const ctrl = new UserController();
const input = process.argv[2];
ctrl.getProfile(input);
ctrl.deleteUser(input);
ctrl.runCommand(input);
