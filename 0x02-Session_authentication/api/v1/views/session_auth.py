#!/usr/bin/env python3
""" Module of Session views
"""
from flask import jsonify, abort, request
from api.v1.views import app_views
from models.user import User
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def auth_sesion():
    """ POST /auth_session/login
    Return:
      - the user
    """
    email = request.form.get('email', None)
    password = request.form.get('password', None)
    if email is None or email == '':
        return jsonify({"error": "email missing"}), 400
    if password is None or password == '':
        return jsonify({"error": "password missing"}), 400
    users = User.search({"email": email})
    if not users or users == []:
        return jsonify({"error": "no user found for this email"}), 404
    for u in users:
        if not u.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401
        from api.v1.app import auth

        cookie_id = str(auth.create_session(u.id))
        response = jsonify(u.to_json())
        session_name = os.getenv('SESSION_NAME')
        response.set_cookie(session_name, cookie_id)
        return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def handle_logout():
    """
    Handle user logout
    """
    from api.v1.app import auth
    if auth.destroy_session(request):
        return jsonify({}), 200
    abort(404)
