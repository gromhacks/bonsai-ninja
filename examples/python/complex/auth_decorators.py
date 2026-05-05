"""Auth decorator patterns for testing decorator flow analysis."""

import functools
import hashlib
import os


# --- Auth decorators ---

def login_required(f):
    """Decorator that requires authentication."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user_id = get_session_user()
        if not user_id:
            return {"error": "Unauthorized"}, 401
        return f(*args, **kwargs)
    return wrapper


def admin_only(f):
    """Decorator that requires admin role."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user.get("role") != "admin":
            return {"error": "Forbidden"}, 403
        return f(*args, **kwargs)
    return wrapper


def rate_limit(max_calls=10):
    """Decorator factory with arguments for rate limiting."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            # VULN: no actual rate limiting check
            return f(*args, **kwargs)
        return wrapper
    return decorator


# --- Helpers ---

def get_session_user():
    return os.environ.get("USER_ID")


def get_current_user():
    uid = os.environ.get("USER_ID")
    if uid:
        return {"id": uid, "role": "user"}
    return None


# --- Routes using auth decorators ---

@login_required
def get_profile(user_id):
    """VULN: IDOR -- no check that user_id matches session user."""
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)


@login_required
@rate_limit(max_calls=5)
def change_password(old_password, new_password):
    """Stacked decorators: login + rate limit."""
    uid = get_session_user()
    hashed = hashlib.md5(new_password.encode()).hexdigest()  # VULN: weak hash
    query = f"UPDATE users SET password = '{hashed}' WHERE id = {uid}"
    return execute_query(query)


@admin_only
def delete_user(target_id):
    """VULN: SQL injection in admin-only endpoint."""
    query = "DELETE FROM users WHERE id = " + target_id
    return execute_query(query)


@admin_only
def run_command(cmd):
    """VULN: command injection in admin-only endpoint."""
    return os.popen(cmd).read()


def execute_query(query):
    """Simulated DB query (sink)."""
    return {"result": query}
