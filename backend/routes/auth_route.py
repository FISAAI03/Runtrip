from flask import Blueprint, request, jsonify
from database import Database
from models.user_model import UserModel
from services.auth_service import AuthService

auth_bp = Blueprint('auth', __name__)

# 의존성 주입
db = Database()
user_model = UserModel(db)
auth_service = AuthService(user_model)

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "입력 값이 부족합니다."}), 400

    result, error = auth_service.login(email, password)

    if error:
        return jsonify({"success": False, "message": error}), 401

    return jsonify({
        "success": True,
        "message": "로그인 성공",
        "token": result["token"],
        "user": result["user"]
    }), 200

@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    success, message = auth_service.signup(data)

    if not success:
        status_code = 409 if "이미 가입된" in message else 400
        return jsonify({"success": False, "message": message}), status_code

    return jsonify({"success": True, "message": message}), 201