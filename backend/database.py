import mysql.connector
from config import Config

class Database:
    def __init__(self):
        self.config = {
            'host': Config.DB_HOST,
            'port': Config.DB_PORT,
            'user': Config.DB_USER,
            'password': Config.DB_PASSWORD,
            'database': Config.DB_NAME
        }

    def get_connection(self):
        """DB 커넥션을 생성하여 반환"""
        return mysql.connector.connect(**self.config)