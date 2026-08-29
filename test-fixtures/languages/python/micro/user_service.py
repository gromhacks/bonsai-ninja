from .auth_service import verify_token, run_admin_command


def get_user(token):
    user_id = verify_token(token)
    return {"id": user_id, "token": token}


def update_user(token, action):
    user_id = verify_token(token)
    if user_id:
        run_admin_command(user_id, action)
    return user_id
