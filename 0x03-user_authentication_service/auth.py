#!/usr/bin/env python3
"""Auth module that handles authentication related tasks
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initialize the Auth instance with a database instance"""
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
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
            # Check if the user already exists by searching by email
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # No user found with the email, proceed with registration
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(
                email, hashed_password.decode('utf-8'))
            return new_user

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

            # Compare the provided password with the stored hashed password
            if bcrypt.checkpw(password.encode(
                    'utf-8'), user.hashed_password.encode('utf-8')):
                return True
            return False
        except NoResultFound:
            # Return Flase if no user is found with the provided email
            return False
