import bcrypt
import jwt
from datetime import datetime, timedelta
from config import Config

class AuthService:
    def __init__(self, user_model):
        self.user_model = user_model

    def login(self, email, password):
        # 1. 사용자 조회
        user = self.user_model.find_by_email(email)
        if not user:
            return None, "이메일 또는 비밀번호가 올바르지 않습니다."

        # 2. 비밀번호 확인
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return None, "이메일 또는 비밀번호가 올바르지 않습니다."

        # 3. 토큰 발급
        payload = {
            "user_id": user["id"],
            "email": user["email"],
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        token = jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.JWT_ALGORITHM)

        # 4. 반환할 유저 정보 (비밀번호 제외)
        user_info = {
            "id": user["id"],
            "email": user["email"],
            "nickname": user["nickname"],
            "running_level": user["running_level"],
            "city": user["city"],
        }
        
        return {"token": token, "user": user_info}, None

    def signup(self, data):
        email = data.get("email")
        password = data.get("password")
        nickname = data.get("nickname")

        if not email or not password or not nickname:
            return False, "이메일, 비밀번호, 닉네임은 필수입니다."

        # 중복 확인
        if self.user_model.check_email_exists(email):
            return False, "이미 가입된 이메일입니다."

        # 비밀번호 해시
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        data['password_hash'] = password_hash

        # DB 저장
        self.user_model.create_user(data)
        return True, "회원가입 완료"