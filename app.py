import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "school_social.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

APPROVAL_PENDING = "pending"
APPROVAL_APPROVED = "approved"
APPROVAL_REJECTED = "rejected"

ALLOWED_ROLES = {
    "student_active": "Ученик (учащ)",
    "student_graduate": "Ученик (завършил)",
    "teacher": "Учител",
    "vice_principal": "Зам.-директор",
    "principal": "Директор",
    "sysadmin": "Системен администратор",
}

ROLE_LEVELS = {"student_active": 1, "student_graduate": 1, "teacher": 2, "vice_principal": 3, "principal": 4, "sysadmin": 5}

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-in-production"
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


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


def query_one(query, params=()):
    return get_db().execute(query, params).fetchone()


def query_all(query, params=()):
    return get_db().execute(query, params).fetchall()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS school_directory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            class_name TEXT NOT NULL,
            graduation_year INTEGER,
            is_graduate INTEGER NOT NULL DEFAULT 0,
            UNIQUE(full_name, class_name, graduation_year)
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
            avatar_path TEXT,
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
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT,
            image_path TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS follow_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            UNIQUE(requester_id, target_id),
            FOREIGN KEY(requester_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(target_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    if cur.execute("SELECT COUNT(*) FROM school_directory").fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO school_directory(full_name,class_name,graduation_year,is_graduate) VALUES (?,?,?,?)",
            [
                ("Иван Петров Иванов", "12A", 2024, 1),
                ("Мария Георгиева Димитрова", "11Б", None, 0),
                ("Николай Стоянов Николов", "10В", None, 0),
                ("Антония Христова Иванова", "12Б", 2023, 1),
            ],
        )

    if not cur.execute("SELECT 1 FROM users WHERE role='sysadmin' LIMIT 1").fetchone():
        cur.execute(
            "INSERT INTO users(full_name,class_name,graduation_year,role,email,password_hash,approval_status,created_at) VALUES (?,?,?,?,?,?,?,?)",
            ("System Admin", "", None, "sysadmin", "admin@school.local", generate_password_hash("admin123"), APPROVAL_APPROVED, now_iso()),
        )
    db.commit()
    db.close()


def current_user():
    uid = session.get("user_id")
    return query_one("SELECT * FROM users WHERE id=?", (uid,)) if uid else None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user["approval_status"] != APPROVAL_APPROVED:
            flash("Профилът ви е в изчакване или отхвърлен. Нямате достъп до системата.", "error")
            session.clear()
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


def can_view_profile(viewer, profile):
    if not profile["is_private"]:
        return True
    if viewer and (viewer["id"] == profile["id"] or ROLE_LEVELS.get(viewer["role"], 0) >= 2):
        return True
    if not viewer:
        return False
    rel = query_one(
        "SELECT 1 FROM follow_requests WHERE requester_id=? AND target_id=? AND status='approved'",
        (viewer["id"], profile["id"]),
    )
    return bool(rel)


@app.route("/")
def index():
    return redirect(url_for("feed")) if session.get("user_id") else render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
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

        dir_match = query_one(
            "SELECT * FROM school_directory WHERE lower(full_name)=lower(?) AND class_name=? AND (graduation_year IS ? OR graduation_year=?)",
            (full_name, class_name, graduation_year, graduation_year),
        )
        if role.startswith("student"):
            approval_status = APPROVAL_APPROVED if dir_match else APPROVAL_PENDING
        else:
            approval_status = APPROVAL_PENDING

        try:
            get_db().execute(
                "INSERT INTO users(full_name,class_name,graduation_year,role,email,password_hash,approval_status,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (full_name, class_name, graduation_year, role, email, generate_password_hash(password), approval_status, now_iso()),
            )
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("Този имейл вече съществува.", "error")
            return redirect(url_for("register"))

        flash("Регистрацията е успешна. При нужда профилът ви ще чака одобрение.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", roles=ALLOWED_ROLES)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = query_one("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),))
        if not user or not check_password_hash(user["password_hash"], request.form["password"]):
            flash("Грешен имейл или парола.", "error")
            return redirect(url_for("login"))
        if user["approval_status"] != APPROVAL_APPROVED:
            flash("Профилът ви още не е одобрен.", "error")
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
    user = current_user()
    posts = query_all(
        "SELECT p.*,u.full_name,u.role,u.is_private FROM posts p JOIN users u ON u.id=p.user_id WHERE u.approval_status='approved' ORDER BY p.created_at DESC"
    )
    visible_posts = [p for p in posts if can_view_profile(user, p)]
    stories = query_all(
        "SELECT s.*,u.full_name,u.is_private FROM stories s JOIN users u ON u.id=s.user_id WHERE s.expires_at>? ORDER BY s.created_at DESC",
        (now_iso(),),
    )
    visible_stories = [s for s in stories if can_view_profile(user, s)]
    return render_template("feed.html", user=user, posts=visible_posts, stories=visible_stories, role_labels=ALLOWED_ROLES)


def save_uploaded(file_obj, prefix=""):
    filename = secure_filename(file_obj.filename)
    filename = f"{prefix}{datetime.utcnow().timestamp()}_{filename}"
    file_obj.save(UPLOAD_DIR / filename)
    return f"uploads/{filename}"


@app.route("/post", methods=["POST"])
@login_required
def create_post():
    content = request.form["content"].strip()
    if not content:
        flash("Постът не може да е празен.", "error")
        return redirect(url_for("feed"))
    image = request.files.get("image")
    image_path = save_uploaded(image) if image and image.filename else None
    get_db().execute("INSERT INTO posts(user_id,content,image_path,created_at) VALUES (?,?,?,?)", (session["user_id"], content, image_path, now_iso()))
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
    image_path = save_uploaded(image, "story_") if image and image.filename else None
    get_db().execute(
        "INSERT INTO stories(user_id,content,image_path,expires_at,created_at) VALUES (?,?,?,?,?)",
        (session["user_id"], content, image_path, (datetime.utcnow() + timedelta(hours=24)).isoformat(timespec="seconds"), now_iso()),
    )
    get_db().commit()
    return redirect(url_for("feed"))


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    viewer = current_user()
    profile_user = query_one("SELECT * FROM users WHERE id=?", (user_id,))
    if not profile_user:
        return "Not found", 404
    visible = can_view_profile(viewer, profile_user)
    posts = query_all("SELECT * FROM posts WHERE user_id=? ORDER BY created_at DESC", (user_id,)) if visible else []
    relation = query_one("SELECT * FROM follow_requests WHERE requester_id=? AND target_id=?", (viewer["id"], user_id)) if viewer["id"] != user_id else None
    followers = query_one("SELECT COUNT(*) c FROM follow_requests WHERE target_id=? AND status='approved'", (user_id,))["c"]
    following = query_one("SELECT COUNT(*) c FROM follow_requests WHERE requester_id=? AND status='approved'", (user_id,))["c"]
    return render_template("profile.html", profile=profile_user, posts=posts, visible=visible, relation=relation, labels=ALLOWED_ROLES, followers=followers, following=following)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    user = current_user()
    if request.method == "POST":
        avatar = request.files.get("avatar")
        avatar_path = user["avatar_path"]
        if avatar and avatar.filename:
            avatar_path = save_uploaded(avatar, "avatar_")
        get_db().execute(
            "UPDATE users SET bio=?,workplace=?,is_private=?,avatar_path=? WHERE id=?",
            (request.form.get("bio", "").strip(), request.form.get("workplace", "").strip(), 1 if request.form.get("is_private") else 0, avatar_path, user["id"]),
        )
        get_db().commit()
        flash("Профилът е обновен.", "success")
        return redirect(url_for("profile", user_id=user["id"]))
    return render_template("edit_profile.html", user=user)


@app.route("/follow/<int:target_id>", methods=["POST"])
@login_required
def follow(target_id):
    me = current_user()
    target = query_one("SELECT * FROM users WHERE id=?", (target_id,))
    if not target or target_id == me["id"]:
        return redirect(url_for("feed"))
    status = "approved" if not target["is_private"] else "pending"
    get_db().execute(
        "INSERT OR REPLACE INTO follow_requests(requester_id,target_id,status,created_at) VALUES (?,?,?,?)",
        (me["id"], target_id, status, now_iso()),
    )
    get_db().commit()
    flash("Изпратено е follow искане." if status == "pending" else "Започнахте да следвате профила.", "success")
    return redirect(url_for("profile", user_id=target_id))


@app.route("/follow/review", methods=["GET", "POST"])
@login_required
def follow_review():
    me = current_user()
    if request.method == "POST":
        fr_id = request.form["fr_id"]
        status = "approved" if request.form["action"] == "approve" else "rejected"
        get_db().execute("UPDATE follow_requests SET status=? WHERE id=? AND target_id=?", (status, fr_id, me["id"]))
        get_db().commit()
    pending = query_all(
        "SELECT fr.*,u.full_name FROM follow_requests fr JOIN users u ON u.id=fr.requester_id WHERE fr.target_id=? AND fr.status='pending' ORDER BY fr.created_at DESC",
        (me["id"],),
    )
    return render_template("follow_review.html", pending=pending)


@app.route("/admin/registrations", methods=["GET", "POST"])
@login_required
@role_required(4)
def admin_registrations():
    if request.method == "POST":
        get_db().execute("UPDATE users SET approval_status=? WHERE id=?", ("approved" if request.form["action"] == "approve" else "rejected", request.form["user_id"]))
        get_db().commit()
    pending = query_all("SELECT * FROM users WHERE approval_status='pending' ORDER BY created_at ASC")
    return render_template("admin_registrations.html", pending=pending, labels=ALLOWED_ROLES)


@app.route("/admin/directory", methods=["GET", "POST"])
@login_required
@role_required(4)
def admin_directory():
    if request.method == "POST":
        get_db().execute(
            "INSERT INTO school_directory(full_name,class_name,graduation_year,is_graduate) VALUES (?,?,?,?)",
            (request.form["full_name"].strip(), request.form["class_name"].strip(), request.form.get("graduation_year") or None, 1 if request.form.get("is_graduate") else 0),
        )
        get_db().commit()
    rows = query_all("SELECT * FROM school_directory ORDER BY id DESC")
    return render_template("admin_directory.html", rows=rows)


@app.context_processor
def inject_common():
    return {"ROLE_LEVELS": ROLE_LEVELS, "ALLOWED_ROLES": ALLOWED_ROLES, "current_user": current_user()}


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
