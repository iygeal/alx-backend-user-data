#!/usr/bin/env python3
"""Auth module that handles authentication related tasks
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> bytes:
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


def _generate_uuid() -> str:
    """Generates a new uuid and returns it as a string."""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Initialize the Auth instance with a database instance."""
        self._db = DB()

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
            hashed_password = _hash_password(password)
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

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session by setting session_id to None for a given user.

        Args:
            user_id (int): The user's ID whose session should be destroyed.

        Returns:
            None
        """
        try:
            # Find the user by id
            user = self._db.find_user_by(id=user_id)

            # Set the user's session_id to None
            self._db.update_user(user.id, session_id=None)

        except NoResultFound:
            # Return None if no user is found with the provided id
    def create_session(self, email: str) -> str:
        """Generate session ID for a user and return it.

        Args:
            email (str): The user's email.

        Returns:
            str: The session ID or None if the user is not found.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Returns the User associated with the given session ID.

        Args:
            session_id (str): The session ID to query.

        Returns:
            User | None: User object if found, else None.
        """
        if session_id is None:
            return None
        try:
            # Query the db for a user with the given session_id
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None
