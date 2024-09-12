#!/usr/bin/env python3
"""
This module provides logging with field redaction for sensitive information.
"""

import logging
from typing import List
import re


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
