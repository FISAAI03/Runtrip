from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
import os
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
CORS(app)  # Flutter에서 호출할 수 있게 CORS 열기

def get_db():
    conn = mysql.connector.connect(
        host="221.155.195.6",
        port=53306,
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
    )
    return conn

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "이메일과 비밀번호를 입력해주세요."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1) 이메일로 사용자 조회
    cursor.execute(
        """
        SELECT id, email, password_hash, nickname, running_level, city
        FROM users
        WHERE email = %s
        """,
        (email,),
    )
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"success": False, "message": "이메일 또는 비밀번호가 올바르지 않습니다."}), 401

    # 2) 비밀번호 확인
    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"success": False, "message": "이메일 또는 비밀번호가 올바르지 않습니다."}), 401

    # 3) JWT 토큰 발급
    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "exp": datetime.utcnow() + timedelta(days=7),  # 7일 유효
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET"), algorithm="HS256")

    # 4) 응답 (토큰 + 간단한 프로필)
    return jsonify({
        "success": True,
        "message": "로그인 성공",
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "nickname": user["nickname"],
            "running_level": user["running_level"],
            "city": user["city"],
        }
    }), 200


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    email = data.get("email")
    password = data.get("password")
    nickname = data.get("nickname")

    # 추가된 필드들
    full_name = data.get("full_name")
    birth_year = data.get("birth_year")
    gender = data.get("gender")
    city = data.get("city")
    running_level = data.get("running_level")  # 'BEGINNER' / 'INTERMEDIATE' / 'ADVANCED'
    preferred_distance_km = data.get("preferred_distance_km")
    weekly_goal_runs = data.get("weekly_goal_runs")

    # 1) 기본 검증
    if not email or not password or not nickname:
        return jsonify({"success": False, "message": "이메일, 비밀번호, 닉네임은 필수입니다."}), 400

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 2) 이메일 중복 확인
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    existing = cursor.fetchone()
    if existing:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "message": "이미 가입된 이메일입니다."}), 409

    # 3) 비밀번호 해시
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    password_hash = password_hash.decode("utf-8")

    # 4) INSERT
    cursor.execute(
        """
        INSERT INTO users (
            email, password_hash, nickname,
            full_name, birth_year, gender, city,
            running_level, preferred_distance_km, weekly_goal_runs
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            email,
            password_hash,
            nickname,
            full_name,
            birth_year,
            gender,
            city,
            running_level,
            preferred_distance_km,
            weekly_goal_runs,
        ),
    )

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "message": "회원가입 완료"}), 201



if __name__ == "__main__":
    # 개발용
    app.run(host="0.0.0.0", port=5000, debug=True)
