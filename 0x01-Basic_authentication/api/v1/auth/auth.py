#!/usr/bin/env python3
"""This module handles basic authentication for the API"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Template which handles authentication for the API"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determines if authentication is required for a given path.
        Returns True if the path is not in the excluded_paths
        """
        if path is None:
            return True

        if not excluded_paths or len(excluded_paths) == 0:
            return True

        # Ensure both path and excluded_paths are handled with or without
        # trailing slashes
        path = path.rstrip('/')

        # Check if the path (with or without trailing slash)
        # is in excluded_paths
        for excluded_path in excluded_paths:
            if excluded_path.rstrip('/') == path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Retrieves the authorization header from a request.
        If no Authorization header is present, returns None.
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the current user from a request."""
        return None
