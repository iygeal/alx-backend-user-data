#!/usr/bin/env python3
"""
Module for password hashing using bcrypt
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password with a salted bcrypt hash.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    # Encode the password to bytes
    password_bytes = password.encode('utf-8')
    # Generate a salt and hash the password
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed_password
