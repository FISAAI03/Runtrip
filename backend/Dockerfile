# 1. Base Image 선택: Python 3.12 Slim 버전 사용
FROM python:3.12-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 필요한 시스템 패키지 설치
# bcrypt 등 일부 패키지는 컴파일이 필요할 수 있어 개발 도구들을 미리 설치합니다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    musl-dev \
    && rm -rf /var/lib/apt/lists/*


# 4. 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 소스 코드 전체 복사 (models, routes 등 포함)
COPY . .

# 6. 포트 노출 (Flask 기본 포트)
EXPOSE 5000

# 7. 실행 명령어 (개발용)
CMD ["python", "app.py"]