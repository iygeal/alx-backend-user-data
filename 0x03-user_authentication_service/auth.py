#!/usr/bin/env python3
"""Auth module that handles authentication related tasks
"""

import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt's hashing algo and
    returns hashed password as bytes

    Args:
        password (str): The password to hash

    Returns:
        bytes: The hashed password
    """
    # Generate a salt
    salt: bytes = bcrypt.gensalt()

    # Hash the password usin the generated salt
    hashed_password: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password
