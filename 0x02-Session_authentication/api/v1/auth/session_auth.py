#!/usr/bin/env python3
""" This module handles session authentication for the API """
from api.v1.auth.auth import Auth
from uuid import uuid4


class SessionAuth(Auth):
    """ This class handles session authentication for the API """

    # Class attribute to store session IDs and corresponding user IDs
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a session ID for a given user ID and stores it

        Args:
            user_id (str): The ID of the user for whom
            the session is created.

        Returns:
            str: The session ID generated, or None if input is invalid.
        """
        if user_id is None or not isinstance(user_id, str):
            return None

        # Generate a session ID using uuid4
        session_id = str(uuid4())

        # Store the session ID with the user ID in the dictionary
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Retrieves the user ID associated with a given session ID

        Args:
            session_id (str): The session ID to retrieve the user ID for.

        Returns:
            str: The user ID associated with the session ID, or None
            if the session ID is invalid or not found.
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)
