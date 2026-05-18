import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "school_social.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_ROLES = {
    "student_active": "Ученик (учащ)",
    "student_graduate": "Ученик (завършил)",
    "teacher": "Учител",
    "vice_principal": "Зам.-директор",
    "principal": "Директор",
    "sysadmin": "Системен администратор",
}

ROLE_LEVELS = {
    "student_active": 1,
    "student_graduate": 1,
    "teacher": 2,
    "vice_principal": 3,
    "principal": 4,
    "sysadmin": 5,
}

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-in-production"
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS school_directory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            class_name TEXT NOT NULL,
            graduation_year INTEGER,
            is_graduate INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            class_name TEXT,
            graduation_year INTEGER,
            role TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            bio TEXT DEFAULT '',
            workplace TEXT DEFAULT '',
            is_private INTEGER NOT NULL DEFAULT 0,
            approval_status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            image_path TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT,
            image_path TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS follow_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            UNIQUE(requester_id, target_id)
        );
        """
    )

    existing = cur.execute("SELECT COUNT(*) c FROM school_directory").fetchone()[0]
    if existing == 0:
        rows = [
            ("Иван Петров Иванов", "12A", 2024, 1),
            ("Мария Георгиева Димитрова", "11Б", None, 0),
            ("Николай Стоянов Николов", "10В", None, 0),
            ("Антония Христова Иванова", "12Б", 2023, 1),
        ]
        cur.executemany(
            "INSERT INTO school_directory(full_name,class_name,graduation_year,is_graduate) VALUES (?,?,?,?)",
            rows,
        )

    admin_exists = cur.execute("SELECT 1 FROM users WHERE role='sysadmin' LIMIT 1").fetchone()
    if not admin_exists:
        cur.execute(
            """
            INSERT INTO users(full_name, class_name, graduation_year, role, email, password_hash, approval_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'approved', ?)
            """,
            (
                "System Admin",
                "",
                None,
                "sysadmin",
                "admin@school.local",
                generate_password_hash("admin123"),
                datetime.utcnow().isoformat(),
            ),
        )
    db.commit()
    db.close()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


def role_required(min_level):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or ROLE_LEVELS.get(user["role"], 0) < min_level:
                flash("Нямате права за тази операция.", "error")
                return redirect(url_for("feed"))
            return f(*args, **kwargs)

        return wrapper

    return decorator


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def can_view_profile(viewer, profile):
    if not profile["is_private"]:
        return True
    if viewer and viewer["id"] == profile["id"]:
        return True
    if viewer and ROLE_LEVELS.get(viewer["role"], 0) >= 2:
        return True
    if not viewer:
        return False
    fr = get_db().execute(
        "SELECT 1 FROM follow_requests WHERE requester_id=? AND target_id=? AND status='approved'",
        (viewer["id"], profile["id"]),
    ).fetchone()
    return bool(fr)


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("feed"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        full_name = request.form["full_name"].strip()
        class_name = request.form.get("class_name", "").strip()
        graduation_year = request.form.get("graduation_year") or None
        role = request.form["role"]
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if role not in ALLOWED_ROLES:
            flash("Невалидна роля.", "error")
            return redirect(url_for("register"))

        if len(full_name.split()) < 3:
            flash("Изискват се три имена.", "error")
            return redirect(url_for("register"))

        if role.startswith("student") and not class_name:
            flash("За ученик е задължителен клас.", "error")
            return redirect(url_for("register"))

        dir_match = db.execute(
            """
            SELECT * FROM school_directory
            WHERE lower(full_name)=lower(?) AND class_name=?
              AND (graduation_year IS ? OR graduation_year=?)
            """,
            (full_name, class_name, graduation_year, graduation_year),
        ).fetchone()

        approval_status = "approved" if dir_match or role in {"teacher", "vice_principal", "principal", "sysadmin"} else "pending"

        try:
            db.execute(
                """
                INSERT INTO users(full_name,class_name,graduation_year,role,email,password_hash,approval_status,created_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    full_name,
                    class_name,
                    graduation_year,
                    role,
                    email,
                    generate_password_hash(password),
                    approval_status,
                    datetime.utcnow().isoformat(),
                ),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Този имейл вече съществува.", "error")
            return redirect(url_for("register"))

        flash("Регистрацията е успешна. Влезте в профила си.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", roles=ALLOWED_ROLES)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Грешен имейл или парола.", "error")
            return redirect(url_for("login"))

        if user["approval_status"] == "rejected":
            flash("Регистрацията ви е отхвърлена.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        return redirect(url_for("feed"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/feed")
@login_required
def feed():
    db = get_db()
    user = current_user()
    posts = db.execute(
        """
        SELECT p.*, u.full_name, u.role FROM posts p
        JOIN users u ON p.user_id=u.id
        WHERE u.approval_status='approved'
        ORDER BY p.created_at DESC
        """
    ).fetchall()

    stories = db.execute(
        """
        SELECT s.*, u.full_name FROM stories s JOIN users u ON u.id=s.user_id
        WHERE s.expires_at > ? ORDER BY s.created_at DESC
        """,
        (datetime.utcnow().isoformat(),),
    ).fetchall()
    return render_template("feed.html", user=user, posts=posts, stories=stories, role_labels=ALLOWED_ROLES)


@app.route("/post", methods=["POST"])
@login_required
def create_post():
    content = request.form["content"].strip()
    image = request.files.get("image")
    image_path = None
    if image and image.filename:
        filename = f"{datetime.utcnow().timestamp()}_{secure_filename(image.filename)}"
        image.save(UPLOAD_DIR / filename)
        image_path = f"uploads/{filename}"

    get_db().execute(
        "INSERT INTO posts(user_id,content,image_path,created_at) VALUES (?,?,?,?)",
        (session["user_id"], content, image_path, datetime.utcnow().isoformat()),
    )
    get_db().commit()
    return redirect(url_for("feed"))


@app.route("/story", methods=["POST"])
@login_required
def create_story():
    content = request.form.get("content", "").strip()
    image = request.files.get("image")
    if not content and (not image or not image.filename):
        flash("Сторито трябва да има текст или снимка.", "error")
        return redirect(url_for("feed"))

    image_path = None
    if image and image.filename:
        filename = f"story_{datetime.utcnow().timestamp()}_{secure_filename(image.filename)}"
        image.save(UPLOAD_DIR / filename)
        image_path = f"uploads/{filename}"

    get_db().execute(
        "INSERT INTO stories(user_id,content,image_path,expires_at,created_at) VALUES (?,?,?,?,?)",
        (
            session["user_id"],
            content,
            image_path,
            (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            datetime.utcnow().isoformat(),
        ),
    )
    get_db().commit()
    return redirect(url_for("feed"))


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    db = get_db()
    viewer = current_user()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return "Not Found", 404

    visible = can_view_profile(viewer, user)
    posts = []
    if visible:
        posts = db.execute("SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    return render_template("profile.html", profile=user, posts=posts, visible=visible, labels=ALLOWED_ROLES)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    db = get_db()
    user = current_user()
    if request.method == "POST":
        db.execute(
            "UPDATE users SET bio=?, workplace=?, is_private=? WHERE id=?",
            (
                request.form.get("bio", ""),
                request.form.get("workplace", ""),
                1 if request.form.get("is_private") else 0,
                user["id"],
            ),
        )
        db.commit()
        return redirect(url_for("profile", user_id=user["id"]))
    return render_template("edit_profile.html", user=user)


@app.route("/admin/registrations", methods=["GET", "POST"])
@login_required
@role_required(4)
def admin_registrations():
    db = get_db()
    if request.method == "POST":
        user_id = request.form["user_id"]
        action = request.form["action"]
        status = "approved" if action == "approve" else "rejected"
        db.execute("UPDATE users SET approval_status=? WHERE id=?", (status, user_id))
        db.commit()
        return redirect(url_for("admin_registrations"))

    pending = db.execute("SELECT * FROM users WHERE approval_status='pending' ORDER BY created_at ASC").fetchall()
    return render_template("admin_registrations.html", pending=pending, labels=ALLOWED_ROLES)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
