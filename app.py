from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, DateTime, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_httpauth import HTTPBasicAuth
from datetime import datetime, timezone, timedelta
import jwt
import os
import dotenv
import smtplib
from email.mime.text import MIMEText
import random

dotenv.load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")

class Base(DeclarativeBase):
    pass

db_url = os.getenv("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url

db = SQLAlchemy(model_class=Base)
db.init_app(app)
migrate = Migrate(app, db)

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return user
    return None

class User(db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))

class OTP(db.Model):
    __tablename__ = "otp_verification"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(120), nullable=False)
    otp_code: Mapped[str] = mapped_column(String(6), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    verified: Mapped[bool] = mapped_column(default=False)

with app.app_context():
    db.create_all()
    
EMAIL_ADDRESS = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASS")

def send_email(receiver_email, otp_code):
    from email.mime.text import MIMEText

    msg = MIMEText(f"Your login OTP is: {otp_code}\nIt will expire in 3 minutes.")
    msg["Subject"] = "Your OTP for Login"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = receiver_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)



@app.route("/register", methods=["POST"])
def register():
    if not request.is_json:
        return {"error": "Request must be JSON"}, 400
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not username or not password or not email:
        return {"error": "Username, password and email required"}, 400

    if User.query.filter_by(username=username).first():
        return {"message": "Username already exists"}, 409
    if User.query.filter_by(email=email).first():
        return {"message": "Email already registered"}, 409

    new_user = User(
        username=username,
        password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8),
        email=email
    )
    db.session.add(new_user)
    db.session.commit()

    return {"message": "User registered successfully"}, 201

@app.route("/login", methods=["POST"]) 
def login(): 
    if request.method == "POST": 
        if not request.is_json: return {"error": "Request must be JSON"}, 400 
        data = request.get_json() 
        username = data.get("username") 
        original_password = data.get("password") 
        if not username or not original_password: 
            return {"error": "Username and password are required"}, 400 
        user = User.query.filter_by(username=username).first() 
        if user and check_password_hash(user.password, original_password): 
            token = jwt.encode( { "user_id": user.id, "exp": datetime.now(timezone.utc) + timedelta(hours=1) }, app.config["SECRET_KEY"], algorithm="HS256" ) 
            return {"token": token}, 200 
        else: 
            return {"message": "Invalid username or password"}, 401

@app.route("/request-otp", methods=["POST"])
def request_otp():
    data = request.get_json()
    email = data.get("email")

    user = User.query.filter_by(email=email).first()
    if not user:
        return {"error": "No user with this email"}, 404

    otp_code = str(random.randint(100000, 999999))
    expiry = datetime.now(timezone.utc) + timedelta(minutes=3)

    otp_entry = OTP(email=email, otp_code=otp_code, expires_at=expiry)
    db.session.add(otp_entry)
    db.session.commit()

    send_email(email, otp_code)

    return {"message": "OTP sent to your email!"}, 200

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data.get("email")
    otp_code = data.get("otp")

    otp_entry = OTP.query.filter_by(email=email, otp_code=otp_code, verified=False).first()
    if not otp_entry:
        return {"error": "Invalid OTP"}, 400

    expires_at_aware = otp_entry.expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at_aware:
        return {"error": "OTP expired"}, 400

    otp_entry.verified = True
    db.session.commit()

    user = User.query.filter_by(email=email).first()
    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        },
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

    return {"token": token}, 200

if __name__ == "__main__":
    app.run(debug=True)
