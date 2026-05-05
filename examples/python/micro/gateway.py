from flask import request
from .user_service import get_user, update_user


def audited(func):
    return func


@audited
def handle_request():
    token = request.args.get("token")  # source: user input
    action = request.args.get("action")  # source: user input

    user = get_user(token)  # flows to SQL injection in auth_service
    result = update_user(token, action)  # flows to command injection in auth_service

    return {"user": user, "result": result}
