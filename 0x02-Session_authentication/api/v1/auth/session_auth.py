#!/usr/bin/env python3
""" Contains the session auth class """
from .auth import Auth
from models.user import User
from typing import TypeVar
import base64
from uuid import uuid4


class SessionAuth(Auth):
    """ subclass of Auth """
    user_id_by_session_id = {}

    def __init__(self) -> None:
        """ Initialize the class """
        super().__init__()

    def create_session(self, user_id: str = None) -> str:
        """ creates session id """
        if user_id is None or not isinstance(user_id, str):
            return None
        sess_id = uuid4()
        session_id = str(sess_id)

        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ retruns user id based on session_id """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id, None)

    def current_user(self, request=None):
        """ retrives the current user """
        cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(cookie)
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """ deletes a session """
        if request is None:
            return False
        session_cookie = self.session_cookie(request)
        if session_cookie is None:
            return False
        user_id = self.user_id_for_session_id(session_cookie)
        if user_id is None:
            return False
        del self.user_id_by_session_id[session_cookie]
        return True
