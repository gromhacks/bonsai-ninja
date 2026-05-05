import os
import re
import hashlib
import hmac
import secrets
import html
import urllib.parse
import base64


def sanitize_input(value):
    """Sanitizes user input by removing dangerous characters"""
    if not isinstance(value, str):
        return str(value)
    cleaned = re.sub(r'[<>"\';&|`$]', '', value)
    return cleaned.strip()


def validate_email(email):
    """Validates email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def hash_password(password):
    """Hashes password with salt"""
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + ":" + hashed.hex()


def verify_password(password, stored):
    """Verifies password against stored hash"""
    salt, hash_hex = stored.split(":", 1)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(hashed.hex(), hash_hex)


def generate_token():
    """Generates a secure random token"""
    return secrets.token_urlsafe(32)


def escape_html(text):
    """Escapes HTML special characters"""
    return html.escape(text)


def sanitize_filename(filename):
    """Sanitizes filename to prevent path traversal"""
    name = os.path.basename(filename)
    name = re.sub(r'[^\w\s\-.]', '', name)
    return name


def sanitize_url(url):
    """Validates and sanitizes URL"""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme")
    if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
        raise ValueError("Internal URL not allowed")
    return url


def encode_base64(data):
    """Encodes data to base64"""
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def decode_base64(data):
    """Decodes base64 data"""
    return base64.b64decode(data)


def format_error(message, details=None):
    """Formats error response"""
    error = {"error": message}
    if details:
        error["details"] = details
    return error


def paginate(items, page, per_page):
    """Paginates a list of items"""
    start = (page - 1) * per_page
    end = start + per_page
    return {
        "items": items[start:end],
        "total": len(items),
        "page": page,
        "per_page": per_page,
        "pages": (len(items) + per_page - 1) // per_page,
    }


def rate_limit_key(request):
    """Generates rate limit key from request"""
    return f"rate:{request.remote_addr}:{request.endpoint}"


class ConfigManager:
    """Application configuration management"""

    def __init__(self):
        self.config = {}

    def load_from_env(self):
        self.config = {
            "database_url": os.environ.get("DATABASE_URL", "sqlite:///app.db"),
            "secret_key": os.environ.get("SECRET_KEY", "dev-key"),
            "debug": os.environ.get("DEBUG", "false").lower() == "true",
            "max_upload_size": int(os.environ.get("MAX_UPLOAD_SIZE", "10485760")),
            "allowed_origins": os.environ.get("ALLOWED_ORIGINS", "*").split(","),
        }

    def get(self, key, default=None):
        return self.config.get(key, default)

    def validate(self):
        required = ["database_url", "secret_key"]
        missing = [k for k in required if k not in self.config]
        if missing:
            raise ValueError(f"Missing config: {missing}")


class ResponseBuilder:
    """Builds HTTP responses"""

    @staticmethod
    def success(data, status=200):
        return {"status": "success", "data": data}, status

    @staticmethod
    def error(message, status=400):
        return {"status": "error", "message": message}, status

    @staticmethod
    def paginated(items, total, page, per_page):
        return {
            "status": "success",
            "data": items,
            "pagination": {
                "total": total,
                "page": page,
                "per_page": per_page,
            },
        }
