#!/usr/bin/env python3
"""Auth module that handles authentication related tasks
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
from sqlalchemy.exc import InvalidRequestError


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initialize the Auth instance with a database instance."""
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hashes a password using bcrypt's hashing algo and
        returns hashed password as bytes.

        Args:
            password (str): The password to hash.

        Returns:
            bytes: The hashed password.
        """
        salt: bytes = bcrypt.gensalt()  # Generate a salt
        hashed_password: bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a user with the given email and password.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            User: The newly created User object.

        Raises:
            ValueError: If the user already exists with the given email.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = self._hash_password(password)
            return self._db.add_user(email, hashed_password)
        except InvalidRequestError:
            raise ValueError("Invalid email or password")

    def valid_login(self, email: str, password: str) -> bool:
        """Check if login credentials are valid.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            bool: True if valid login, else False.
        """
        try:
            # Find user by email
            user = self._db.find_user_by(email=email)

            # Check if the provided password matches the stored hashed password
            if bcrypt.checkpw(password.encode(
                    'utf-8'), user.hashed_password.encode('utf-8')):
                return True
            return False
        except NoResultFound:
            # Return False if no user is found with the provided email
            return False

    def _generate_uuid(self) -> str:
        """Generates a new UUID and returns it as a string."""
        return str(uuid.UUID(str(uuid.uuid4())))
