#!/usr/bin/env python3
"""
Authentication for the API
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """ class to manage the API authentication """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ public method """
        if path is None:
            return True

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        # Normalize the path by removing trailing slashes
        normalized_path = path.rstrip('/')

        for excluded_path in excluded_paths:
            normalized_excluded = excluded_path.rstrip('/')
            if normalized_path == normalized_excluded:
                return False

        # If no match is found, return False
        return True

    def authorization_header(self, request=None) -> str:
        """ public method """
        if request is None:
            return None
        elif not (request.headers.get('Authorization')):
            return None
        else:
            return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ public method """
        return None  # You will implement this method later
