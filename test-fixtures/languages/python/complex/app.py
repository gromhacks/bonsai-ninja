import os
import sys
import json
import pickle
import subprocess
import html
import shlex
import sqlite3
import hashlib
import hmac
import base64
import re
from os.path import join as path_join
from flask import Flask, request, render_template_string, redirect, url_for, jsonify, make_response, session
from services import UserService, DocumentService, AdminService
from database import DatabaseConnection, UserRepository, DocumentRepository
from ml_pipeline import ModelLoader, InferenceEngine, ModelValidator
from utils import sanitize_input, validate_email, hash_password, generate_token

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-me")

db = DatabaseConnection(os.environ.get("DATABASE_URL", "sqlite:///app.db"))
user_repo = UserRepository(db)
doc_repo = DocumentRepository(db)
user_service = UserService(user_repo)
doc_service = DocumentService(doc_repo)
admin_service = AdminService(db)


# ============================================================
# Authentication Routes
# ============================================================

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    user = user_service.authenticate(username, password)
    if user:
        session["user_id"] = user["id"]
        return redirect(url_for("dashboard"))
    return render_template_string("<p>Login failed for {{ name }}</p>", name=username)


@app.route("/register", methods=["POST"])
def register():
    email = request.form["email"]
    username = request.form["username"]
    password = request.form["password"]
    if not validate_email(email):
        return jsonify({"error": "Invalid email"}), 400
    hashed = hash_password(password)
    user_service.create_user(username, email, hashed)
    return redirect(url_for("login"))


@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form["email"]
    token = generate_token()
    user_service.store_reset_token(email, token)
    return jsonify({"message": "Reset email sent"})


# ============================================================
# User Search (VULN: SQL Injection - Deep Chain 1)
# ============================================================

@app.route("/api/users/search")
def search_users():
    """Deep Chain 1 entry: user search query flows through service layers to SQL"""
    query = request.args["query"]
    sort_by = request.args.get("sort", "name")
    limit = request.args.get("limit", "50")
    results = user_service.search(query, sort_by, limit)
    return jsonify(results)


@app.route("/api/users/search/safe")
def search_users_safe():
    """Safe version: uses parameterized queries"""
    query = request.args["query"]
    sort_by = request.args.get("sort", "name")
    results = user_service.search_safe(query, sort_by)
    return jsonify(results)


# ============================================================
# Document Management
# ============================================================

@app.route("/api/documents/upload", methods=["POST"])
def upload_document():
    doc_file = request.files["document"]
    title = request.form["title"]
    user_id = session.get("user_id")
    result = doc_service.upload(doc_file, title, user_id)
    return jsonify(result)


@app.route("/api/documents/<doc_id>/download")
def download_document(doc_id):
    """VULN: Path traversal - user controls filename"""
    filename = request.args["filename"]
    base_dir = "/var/app/documents"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "rb") as f:
        content = f.read()
    response = make_response(content)
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


@app.route("/api/documents/<doc_id>/download/safe")
def download_document_safe(doc_id):
    """Safe version: validates path"""
    filename = request.args["filename"]
    base_dir = "/var/app/documents"
    safe_name = os.path.basename(filename)
    file_path = os.path.join(base_dir, safe_name)
    if not os.path.abspath(file_path).startswith(os.path.abspath(base_dir)):
        return jsonify({"error": "Invalid path"}), 400
    with open(file_path, "rb") as f:
        content = f.read()
    return make_response(content)


# ============================================================
# ML Model Management (VULN: Command Injection - Deep Chain 2)
# ============================================================

@app.route("/api/models/load", methods=["POST"])
def load_model():
    """Deep Chain 2 entry: model path flows through loader to os.system"""
    model_path = request.json["model_path"]
    model_name = request.json.get("name", "unnamed")
    loader = ModelLoader(model_path, model_name)
    result = loader.load()
    return jsonify(result)


@app.route("/api/models/load/safe", methods=["POST"])
def load_model_safe():
    """Safe version: validates and quotes path"""
    model_path = request.json["model_path"]
    model_name = request.json.get("name", "unnamed")
    safe_path = shlex.quote(model_path)
    loader = ModelLoader(safe_path, model_name)
    result = loader.load_safe()
    return jsonify(result)


@app.route("/api/models/predict", methods=["POST"])
def predict():
    model_name = request.json["model"]
    input_data = request.json["data"]
    engine = InferenceEngine(model_name)
    prediction = engine.predict(input_data)
    return jsonify({"prediction": prediction})


# ============================================================
# Admin Panel
# ============================================================

@app.route("/admin/users")
def admin_users():
    """VULN: XSS via unsanitized template rendering"""
    search = request.args.get("search", "")
    users = admin_service.list_users(search)
    template = "<h1>Users matching: " + search + "</h1><ul>"
    for u in users:
        template += "<li>" + u["name"] + "</li>"
    template += "</ul>"
    return render_template_string(template)


@app.route("/admin/users/safe")
def admin_users_safe():
    """Safe version: escapes output"""
    search = request.args.get("search", "")
    safe_search = html.escape(search)
    users = admin_service.list_users(search)
    template = "<h1>Users matching: " + safe_search + "</h1><ul>"
    for u in users:
        template += "<li>" + html.escape(u["name"]) + "</li>"
    template += "</ul>"
    return render_template_string(template)


@app.route("/admin/execute", methods=["POST"])
def admin_execute():
    """VULN: Code injection via eval"""
    expression = request.json["expression"]
    result = eval(expression)
    return jsonify({"result": str(result)})


@app.route("/admin/reports/generate", methods=["POST"])
def generate_report():
    """VULN: Template injection"""
    report_title = request.form["title"]
    report_body = request.form["body"]
    template = "{% extends 'base.html' %}{% block title %}" + report_title + "{% endblock %}{% block content %}" + report_body + "{% endblock %}"
    return render_template_string(template)


# ============================================================
# SSRF via webhook/proxy
# ============================================================

@app.route("/api/webhooks/test", methods=["POST"])
def test_webhook():
    """VULN: SSRF - user controls URL"""
    import requests as http_client
    webhook_url = request.json["url"]
    payload = request.json.get("payload", {})
    response = http_client.post(webhook_url, json=payload)
    return jsonify({"status": response.status_code, "body": response.text})


@app.route("/api/proxy")
def proxy_request():
    """VULN: SSRF via proxy"""
    import requests as http_client
    target_url = request.args["url"]
    resp = http_client.get(target_url)
    return make_response(resp.content)


# ============================================================
# Deserialization
# ============================================================

@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    """VULN: Insecure deserialization"""
    session_data = request.data
    decoded = base64.b64decode(session_data)
    restored = pickle.loads(decoded)
    return jsonify({"session": str(restored)})


# ============================================================
# LDAP Search
# ============================================================

@app.route("/api/directory/search")
def ldap_search():
    """VULN: LDAP injection"""
    import ldap
    username = request.args["username"]
    conn = ldap.initialize("ldap://directory.internal")
    conn.simple_bind_s("cn=app,dc=corp", "password")
    search_filter = "(uid=" + username + ")"
    results = conn.search_s("dc=corp", ldap.SCOPE_SUBTREE, search_filter)
    return jsonify({"results": str(results)})


# ============================================================
# LLM Prompt Injection
# ============================================================

@app.route("/api/ai/chat", methods=["POST"])
def ai_chat():
    """VULN: LLM prompt injection"""
    from services import LLMService
    user_message = request.json["message"]
    system_prompt = "You are a helpful assistant."
    llm = LLMService()
    full_prompt = system_prompt + "\n\nUser: " + user_message
    response = llm.complete(full_prompt)
    return jsonify({"response": response})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
