class UserModel:
    def __init__(self, db):
        self.db = db

    def find_by_email(self, email):
        conn = self.db.get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            query = """
                SELECT id, email, password_hash, nickname, running_level, city 
                FROM users 
                WHERE email = %s
            """
            cursor.execute(query, (email,))
            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

    def check_email_exists(self, email):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            return cursor.fetchone() is not None
        finally:
            cursor.close()
            conn.close()

    def create_user(self, user_data):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        try:
            query = """
                INSERT INTO users (
                    email, password_hash, nickname, 
                    full_name, birth_year, gender, city, 
                    running_level, preferred_distance_km, weekly_goal_runs
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(query, (
                user_data['email'],
                user_data['password_hash'],
                user_data['nickname'],
                user_data.get('full_name'),
                user_data.get('birth_year'),
                user_data.get('gender'),
                user_data.get('city'),
                user_data.get('running_level'),
                user_data.get('preferred_distance_km'),
                user_data.get('weekly_goal_runs'),
            ))
            conn.commit()
        finally:
            cursor.close()
            conn.close()