#!/usr/bin/env python3
""" This module handles basic authentication for the API
"""
from api.v1.auth.auth import Auth
import base64


class BasicAuth(Auth):
    """Basic Authentication class"""

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the Base64 encoded authorization header from the
        Authorization HTTP header.

        Args:
            authorization_header (str): The Authorization HTTP header.

        Returns:
            str: The Base64 encoded authorization header.
        """
        if authorization_header is None or not isinstance(
                authorization_header, str
        ):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 encoded authorization header.

        Args:
            base64_authorization_header (str): The Base64 encoded
                authorization header.

        Returns:
            str: The decoded authorization header as a UTF-8 string.
        """
        if base64_authorization_header is None or not isinstance(
                base64_authorization_header, str
        ):
            return None

        try:
            # Decode the Base64 string and return decoded string as UTF-8
            return base64.b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None
