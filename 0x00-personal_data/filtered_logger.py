#!/usr/bin/env python3
"""
This module provides a logger with field redaction for sensitive information
and a database connector that fetches credentials from environment variables.
"""

import logging
import os
import mysql.connector
from typing import List


# Define the fields considered as PII (Personally Identifiable Information)
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the database using credentials
    from environment vars.

    The connection details are fetched from environment variables:
    PERSONAL_DATA_DB_USERNAME, PERSONAL_DATA_DB_PASSWORD,
    PERSONAL_DATA_DB_HOST, PERSONAL_DATA_DB_NAME.

    Returns:
        MySQLConnection: A connection to the MySQL database.
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or "root"
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ""
    host = os.getenv('PERSONAL_DATA_DB_HOST') or "localhost"
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    conn = mysql.connector.connect(user=user,
                                   password=passwd,
                                   host=host,
                                   database=db_name)
    return conn


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Obfuscates specified fields in a log message.

    Args:
        fields (List[str]): List of field names to be obfuscated.
        redaction (str): The string to replace sensitive information with.
        message (str): The log message to be processed.
        separator (str): The character used to separate fields in the message.

    Returns:
        str: The log message with obfuscated fields.
    """
    import re
    return re.sub(rf'({"|".join(fields)})=.*?{separator}',
                  lambda m: f'{m.group(1)}={redaction}{separator}', message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class for filtering PII fields. """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ Initialize the formatter with fields to redact. """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Filters values in incoming log records using filter_datum.
        """
        original_message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, original_message,
                            self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Creates and returns a logger named 'user_data' with custom settings.

    Returns:
        logging.Logger: A configured logger that redacts PII fields.
    """
    # Create logger
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevent log propagation

    # Create a stream handler
    handler = logging.StreamHandler()

    # Attach the custom formatter (RedactingFormatter)
    handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))

    # Add the handler to the logger
    logger.addHandler(handler)

    return logger
