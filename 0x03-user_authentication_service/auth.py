#!/usr/bin/env python3
""" authentication """
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """ takes in a string and
        returns a hased password
    """
    byte_password = password.encode('utf-8')
    return bcrypt.hashpw(byte_password, bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Hashes a password and saves it """
        try:
            usr = self._db.find_user_by(email=email)
            if usr:
                raise ValueError(f'User {email} already exists')
        except NoResultFound:
            usr = self._db.add_user(email, _hash_password(password))
            return usr

    def valid_login(self, email: str, password: str) -> bool:
        """returns true if password is correct """
        try:
            usr = self._db.find_user_by(email=email)
            byte_password = password.encode('utf-8')
            if bcrypt.checkpw(byte_password, usr.hashed_password):
                return True
            return False
        except Exception:
            return False

    def _generate_uuid(self) -> str:
        """ return a str uuid"""
        uid = uuid4()
        return str(uid)

    def create_session(self, email: str) -> str:
        """ stores and returns the session_id """
        try:
            usr = self._db.find_user_by(email=email)
            sess_id = self._generate_uuid()
            self._db.update_user(usr.id, session_id=sess_id)
            return sess_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """ returns a user or none """
        if session_id is None:
            return None
        try:
            usr = self._db.find_user_by(session_id=session_id)
            return usr
        except NoResultFound:
            return None

    def destroy_session(self, user_id) -> None:
        """ update session to None """
        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """ finds user and resets the reset token """
        try:
            usr = self._db.find_user_by(email=email)
            token = self._generate_uuid()
            self._db.update_user(usr.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str):
        """ updates user password """
        try:
            usr = self._db.find_user_by(reset_token=reset_token)
            self._db.update_user(usr.id,
                                 hashed_password=_hash_password(password),
                                 reset_token=None)
        except NoResultFound:
            raise ValueError
