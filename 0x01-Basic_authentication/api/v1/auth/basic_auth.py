#!/usr/bin/env python3
""" Contains the basic auth class """
from .auth import Auth
from models.user import User
from typing import TypeVar
import base64


class BasicAuth(Auth):
    """ subclass of Auth """
    def __init__(self) -> None:
        """ Initialize the class """
        super().__init__()

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ Checks if autorization header is correct """
        if authorization_header is None or not isinstance(authorization_header,
                                                          str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        base64_part = authorization_header.split()[1]
        return base64_part

    def decode_base64_authorization_header(self, base64_authorization_header:
                                           str) -> str:
        """ Decodes base64 string"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode('utf-8')
            return decoded_string
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """ returns username and password """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        user_credentials = decoded_base64_authorization_header.split(':')
        return (user_credentials[0], user_credentials[1])

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ returns user """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({'email': user_email})

        if not users:
            return None

        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """ verifies authorization header and returns user """
        if request is None:
            return None

        auth_header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(auth_header)
        user_credentials = self.extract_user_credentials(base64_header)
        user_email, user_pwd = user_credentials
        user = self.user_object_from_credentials(user_email, user_pwd)
        return user
