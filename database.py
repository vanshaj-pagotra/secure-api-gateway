import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    """
    Creates and returns a connection to the MySQL database.
    All credentials are read from the .env file.
    """
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT")),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD")
        )
        return connection
    except mysql.connector.Error as e:
        print(f"[DB ERROR] Failed to connect to database: {e}")
        raise