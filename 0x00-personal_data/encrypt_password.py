#!/usr/bin/env python3
"""a hash_password function that expects one string argument
    name password and returns a salted, hashed password,
    which is a byte string
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """encrypts password"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """checks that password is hashed_password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
