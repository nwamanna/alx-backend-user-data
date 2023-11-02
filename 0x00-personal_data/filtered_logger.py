#!/usr/bin/env python3
""" a function called filter_datum that
    returns the log message obfuscated
"""
from typing import List
import datetime
import logging
import mysql.connector
import re
import os


def get_db() -> mysql.connector.connection.MySQLConnection:
    name = os.environ.get('PERSONAL_DATA_DB_USERNAME')
    password = os.environ.get('PERSONAL_DATA_DB_PASSWORD')
    host = os.environ.get('PERSONAL_DATA_DB_HOST')
    db = os.environ.get('PERSONAL_DATA_DB_NAME')
    connection = mysql.connector.connect(user=name,
                                         password=password,
                                         host=host,
                                         database=db)
    return connection


def main():
    logger = get_logger()
    # Retrieve a database connection using the get_db function
    connection = get_db()

    try:
        # Create a cursor to interact with the database
        cursor = connection.cursor()

        # Define the fields to be filtered
        filtered_fields = ["name", "email", "phone", "ssn", "password"]

        # Execute a query to retrieve all rows from the users table
        cursor.execute("SELECT * FROM users")

        # Fetch and display each row in a filtered format
        for row in cursor.fetchall():
            row = list(row)
            if isinstance(row[6], datetime.datetime):
                row[6] = row[6].strftime("%Y-%m-%dT%H:%M:%S")
                row[0] = f'name={row[0]}'
                row[1] = f'email={row[1]}'
                row[2] = f'phone={row[2]}'
                row[3] = f'ssn={row[3]}'
                row[4] = f'password={row[4]}'
                row[5] = f'ip={row[5]}'
                row[6] = f'last_login={row[6]}'
                row[7] = f'user_agent={row[7]}'
            filtered_row = filter_datum(
                ["name", "email", "phone", "ssn", "password"],
                "***",
                ";".join(map(str, row)), ";")
            logger.info(filtered_row)

    except Exception as e:
        print(e)
    finally:
        # Close the cursor and the database connection
        cursor.close()
        connection.close()


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """ Return a logger object """
    # Create a logger named "user_data"
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)

    # Create a StreamHandler with RedactingFormatter as the formatter
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    # Add the StreamHandler to the logger
    logger.addHandler(stream_handler)

    # Prevent messages from propagating to other loggers
    logger.propagate = False
    print(type(logger))

    return logger


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """ returns the log message obfuscated """
    for field in fields:
        pattern = f'{field}=(.*?)(?={separator}|$)'
        message = re.sub(pattern, f'{field}={redaction}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ method to filter values in incoming """
        message = record.getMessage()  # Extract the message from the record
        filtered_message = filter_datum(self.fields,
                                        self.REDACTION,
                                        message, self.SEPARATOR)
        filtered_message = filtered_message.replace(self.SEPARATOR,
                                                    f"{self.SEPARATOR} ")
        print(filtered_message)
        record.msg = filtered_message  # Update the message in the LogRecord
        return super().format(record)


if __name__ == "__main__":
    main()
