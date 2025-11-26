from flask import Flask
from flask_cors import CORS
from routes.auth_route import auth_bp

app = Flask(__name__)
CORS(app) # Flutter 연동용

# Blueprint 등록
app.register_blueprint(auth_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)