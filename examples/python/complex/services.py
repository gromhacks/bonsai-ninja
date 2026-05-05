import os
import json
import hashlib
import hmac
import re
import subprocess
import shlex
from database import DatabaseConnection, UserRepository, DocumentRepository, QueryBuilder


class SearchQuery:
    """Builds search queries with validation and filtering"""

    def __init__(self, raw_query, sort_field, limit):
        self.raw_query = raw_query
        self.sort_field = sort_field
        self.limit = limit
        self.filters = []

    def validate(self):
        if len(self.raw_query) > 500:
            raise ValueError("Query too long")
        return self

    def build_filter(self):
        """Builds SQL filter - VULN: unsanitized input flows to SQL"""
        if self.raw_query:
            self.filters.append("name LIKE '%" + self.raw_query + "%'")
        if self.sort_field:
            self.filters.append("ORDER BY " + self.sort_field)
        return self

    def build_filter_safe(self):
        """Safe version: uses parameterized queries"""
        if self.raw_query:
            self.filters.append(("name LIKE ?", "%" + self.raw_query + "%"))
        return self

    def get_sql(self):
        base = "SELECT * FROM users"
        if self.filters:
            conditions = " AND ".join(f for f in self.filters if isinstance(f, str))
            if conditions:
                base += " WHERE " + conditions
        base += " LIMIT " + str(self.limit)
        return base

    def get_parameterized(self):
        base = "SELECT * FROM users WHERE name LIKE ?"
        return base, ["%" + self.raw_query + "%"]


class UserService:
    """User management service"""

    def __init__(self, user_repo):
        self.user_repo = user_repo

    def authenticate(self, username, password):
        user = self.user_repo.find_by_username(username)
        if user and self._verify_password(password, user["password_hash"]):
            return user
        return None

    def _verify_password(self, password, stored_hash):
        computed = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(computed, stored_hash)

    def create_user(self, username, email, password_hash):
        return self.user_repo.create(username, email, password_hash)

    def search(self, query, sort_by, limit):
        """Deep Chain 1 continues: builds query and delegates to repo"""
        search_query = SearchQuery(query, sort_by, limit)
        search_query.validate()
        search_query.build_filter()
        return self.user_repo.find_by_filter(search_query)

    def search_safe(self, query, sort_by):
        """Safe version with parameterized queries"""
        return self.user_repo.find_by_filter_safe(query, sort_by)

    def store_reset_token(self, email, token):
        self.user_repo.update_reset_token(email, token)

    def get_user_profile(self, user_id):
        return self.user_repo.find_by_id(user_id)

    def update_profile(self, user_id, data):
        allowed_fields = ["name", "bio", "avatar_url"]
        updates = {k: v for k, v in data.items() if k in allowed_fields}
        return self.user_repo.update(user_id, updates)


class DocumentService:
    """Document upload and management service"""

    UPLOAD_DIR = "/var/app/uploads"
    ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx", ".txt", ".csv"}

    def __init__(self, doc_repo):
        self.doc_repo = doc_repo

    def upload(self, file_obj, title, user_id):
        filename = file_obj.filename
        ext = os.path.splitext(filename)[1].lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            return {"error": "File type not allowed"}
        save_path = os.path.join(self.UPLOAD_DIR, filename)
        file_obj.save(save_path)
        doc_id = self.doc_repo.create(title, save_path, user_id)
        return {"id": doc_id, "title": title}

    def get_document(self, doc_id):
        return self.doc_repo.find_by_id(doc_id)

    def list_documents(self, user_id, page=1, per_page=20):
        offset = (page - 1) * per_page
        return self.doc_repo.find_by_user(user_id, offset, per_page)

    def delete_document(self, doc_id, user_id):
        doc = self.doc_repo.find_by_id(doc_id)
        if doc and doc["user_id"] == user_id:
            os.unlink(doc["path"])
            self.doc_repo.delete(doc_id)
            return True
        return False


class AdminService:
    """Admin panel service"""

    def __init__(self, db):
        self.db = db

    def list_users(self, search_term=None):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if search_term:
            sql = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"
            cursor.execute(sql)
        else:
            cursor.execute("SELECT * FROM users")
        return [dict(row) for row in cursor.fetchall()]

    def get_system_stats(self):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        user_count = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM documents")
        doc_count = cursor.fetchone()["count"]
        return {"users": user_count, "documents": doc_count}

    def run_maintenance(self, task_name):
        """VULN: Command injection via maintenance task"""
        cmd = "python manage.py " + task_name
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"output": result.stdout, "error": result.stderr}

    def run_maintenance_safe(self, task_name):
        """Safe version: uses list args"""
        allowed_tasks = ["cleanup", "optimize", "backup"]
        if task_name not in allowed_tasks:
            return {"error": "Invalid task"}
        result = subprocess.run(["python", "manage.py", task_name], capture_output=True, text=True)
        return {"output": result.stdout}

    def export_data(self, format_type, query):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        sql = "SELECT * FROM users WHERE " + query
        cursor.execute(sql)
        rows = cursor.fetchall()
        if format_type == "json":
            return json.dumps([dict(r) for r in rows])
        return str(rows)


class LLMService:
    """LLM integration service"""

    def __init__(self):
        self.api_key = os.environ.get("LLM_API_KEY")
        self.model = "gpt-4"

    def complete(self, prompt):
        """Sends prompt to LLM - VULN if prompt contains user input"""
        import requests
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        return response.json()["choices"][0]["message"]["content"]

    def summarize(self, text):
        prompt = f"Summarize the following text:\n\n{text}"
        return self.complete(prompt)


class NotificationService:
    """Sends notifications to users"""

    def __init__(self):
        self.smtp_host = os.environ.get("SMTP_HOST", "localhost")

    def send_email(self, to_address, subject, body):
        """VULN: Command injection via email"""
        cmd = f"sendmail -t {to_address} -s '{subject}'"
        os.system(cmd)

    def send_email_safe(self, to_address, subject, body):
        """Safe: uses subprocess with list args"""
        subprocess.run(["sendmail", "-t", to_address, "-s", subject], input=body.encode())

    def send_sms(self, phone_number, message):
        import requests
        requests.post(
            "https://api.twilio.com/send",
            json={"to": phone_number, "body": message},
        )
