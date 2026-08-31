import os
import re
from datetime import date, timedelta
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import CheckConstraint, ForeignKey, String, Text, Date, DateTime, func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
csrf = CSRFProtect()
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
WORK_TYPES = ("Assignment", "Project", "Exam", "Presentation", "Practical")
LEVELS = ("Low", "Medium", "High")
DIFFICULTIES = ("Easy", "Medium", "Hard")


def password_matches(stored_hash, password):
    """Reject damaged/legacy hashes safely instead of returning a server error."""
    if not isinstance(stored_hash, str) or not stored_hash or not stored_hash.split("$", 1)[0]:
        return False
    try:
        return check_password_hash(stored_hash, password)
    except (TypeError, ValueError):
        return False


class User(db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(190), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    entries: Mapped[list["Feedback"]] = relationship(back_populates="student", cascade="all, delete-orphan")


class Feedback(db.Model):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    subject: Mapped[str] = mapped_column(String(100), nullable=False)
    work_type: Mapped[str] = mapped_column(String(30), nullable=False)
    deadline: Mapped[date] = mapped_column(Date, nullable=False)
    difficulty: Mapped[str] = mapped_column(String(10), nullable=False)
    stress: Mapped[str] = mapped_column(String(10), nullable=False)
    feedback_text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now())
    student: Mapped[User] = relationship(back_populates="entries")
    __table_args__ = (
        CheckConstraint("length(feedback_text) BETWEEN 1 AND 1000", name="valid_feedback_length"),
    )


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    database_url = os.getenv("DATABASE_URL", "sqlite:///balanced_python.db")
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "local-development-change-me"),
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    db.init_app(app)
    csrf.init_app(app)
    with app.app_context():
        db.create_all()

    def login_required(view):
        @wraps(view)
        def wrapped(**kwargs):
            if "user_id" not in session:
                flash("Please log in to add feedback.", "error")
                return redirect(url_for("login"))
            return view(**kwargs)
        return wrapped

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return redirect(url_for("add_feedback" if "user_id" in session else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
            if user and password_matches(user.password_hash, password):
                session.clear(); session["user_id"] = user.id; session["user_name"] = user.full_name
                session.permanent = True
                return redirect(url_for("add_feedback"))
            flash("Email or password is incorrect.", "error")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if not 2 <= len(name) <= 100 or not EMAIL_RE.match(email):
                flash("Enter a valid full name and email.", "error")
            elif len(password) < 8 or password != confirm:
                flash("Passwords must match and contain at least 8 characters.", "error")
            else:
                try:
                    db.session.add(User(full_name=name, email=email, password_hash=generate_password_hash(password)))
                    db.session.commit()
                    flash("Account created successfully. You can now log in.", "success")
                    return redirect(url_for("login"))
                except IntegrityError:
                    db.session.rollback()
                    existing = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
                    if existing and not existing.password_hash.split("$", 1)[0]:
                        existing.full_name = name
                        existing.password_hash = generate_password_hash(password)
                        db.session.commit()
                        flash("Your incomplete account was repaired successfully. You can now log in.", "success")
                        return redirect(url_for("login"))
                    flash("An account already exists for this email.", "error")
        return render_template("register.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            user = db.session.execute(db.select(User).where(User.email == email)).scalar_one_or_none()
            if not user:
                flash("No account was found for this email.", "error")
            elif len(password) < 8 or password != confirm:
                flash("Passwords must match and contain at least 8 characters.", "error")
            else:
                user.password_hash = generate_password_hash(password); db.session.commit()
                flash("Password changed successfully. You can now log in.", "success")
                return redirect(url_for("login"))
        return render_template("forgot_password.html")

    @app.get("/add-feedback")
    @login_required
    def add_feedback():
        return render_template("add_feedback.html", default_date=date.today() + timedelta(days=7), work_types=WORK_TYPES, difficulties=DIFFICULTIES, levels=LEVELS)

    @app.post("/feedback")
    @login_required
    def save_feedback():
        subject = request.form.get("subject", "").strip()
        work_type = request.form.get("work_type", "")
        difficulty = request.form.get("difficulty", "")
        stress = request.form.get("stress", "")
        text = request.form.get("feedback", "").strip()
        try: deadline = date.fromisoformat(request.form.get("deadline", ""))
        except ValueError: deadline = None
        if not (1 <= len(subject) <= 100 and 1 <= len(text) <= 1000 and deadline and work_type in WORK_TYPES and difficulty in DIFFICULTIES and stress in LEVELS):
            flash("Complete every field with valid information.", "error")
            return redirect(url_for("add_feedback"))
        try:
            db.session.add(Feedback(user_id=session["user_id"], subject=subject, work_type=work_type, deadline=deadline, difficulty=difficulty, stress=stress, feedback_text=text))
            db.session.commit(); flash("Feedback saved successfully!", "success")
        except SQLAlchemyError:
            db.session.rollback(); flash("Feedback could not be saved. Please try again.", "error")
        return redirect(url_for("add_feedback"))

    @app.get("/view-feedback")
    def view_feedback():
        rows = db.session.execute(db.select(Feedback).order_by(Feedback.created_at.desc())).scalars().all()
        return render_template("view_feedback.html", rows=rows)

    @app.post("/logout")
    def logout():
        session.clear(); return redirect(url_for("login"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
