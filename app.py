from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from datetime import datetime, timezone, timedelta
import jwt
import os
import dotenv
dotenv.load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

class Base(DeclarativeBase):
    pass

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("POSTGRESQL_DATABASE")
# print("Connected to:", app.config["SQLALCHEMY_DATABASE_URI"])

db = SQLAlchemy(model_class=Base)
db.init_app(app)

auth = HTTPBasicAuth()
@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username = username).first()
    if user and check_password_hash(user.password, password):
        return user  
    return None

class User(db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))

with app.app_context():
    db.create_all()
    
@app.route("/register", methods=["POST"])
def register():
    if request.method == "POST":
        if not request.is_json:
            return {"error": "Request must be JSON"}, 400
        data = request.get_json()
        username = data.get("username")
        original_password = data.get("password")
        if User.query.filter_by(username=username).first():
            return {"message": "Username already exists"}, 409

        if not username or not original_password:
            return {"Credentials Missing" : "Username and Password is required to Register"}, 400
        
        new_user = User(
            username = username,
            password = generate_password_hash(original_password, method='pbkdf2:sha256', salt_length=8)
        )
        db.session.add(new_user)
        db.session.commit()
    
    return {"message": "User registered successfully"}, 201

@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        if not request.is_json:
            return {"error": "Request must be JSON"}, 400

        data = request.get_json()
        username = data.get("username")
        original_password = data.get("password")

        if not username or not original_password:
            return {"error": "Username and password are required"}, 400

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, original_password):
            token = jwt.encode(
                {
                    "user_id": user.id,
                    "exp": datetime.now(timezone.utc) + timedelta(hours=1)
                },
                app.config["SECRET_KEY"],
                algorithm="HS256"
            )
            return {"token": token}, 200
        else:
            return {"message": "Invalid username or password"}, 401

if __name__ == "__main__":
    app.run(debug=True)