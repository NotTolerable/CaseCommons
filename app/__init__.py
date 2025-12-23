import logging
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse, urljoin
from flask import Flask, render_template, redirect, url_for, session, flash, request, abort, send_from_directory
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta
from functools import wraps
import bleach
from werkzeug.utils import secure_filename
import uuid
from sqlalchemy import or_, inspect, text, func

# Extensions
csrf = CSRFProtect()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024


def create_app(test_config=None):
    app = Flask(__name__)

    app.logger.setLevel(logging.INFO)

    def env_flag(name, default=False):
        return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}

    def _normalized_database_uri():
        url = os.environ.get("DATABASE_URL")
        if url and url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        if url:
            return url

        sqlite_path = Path(
            os.environ.get("SQLITE_PATH", os.environ.get("APP_DB_PATH", "/data/app.db"))
        )
        if not sqlite_path.is_absolute():
            sqlite_path = (Path(app.root_path).parent / sqlite_path).resolve()
        return f"sqlite:///{sqlite_path}"

    def _mask_db_uri(uri: str) -> str:
        if not uri:
            return ""
        try:
            parsed = urlparse(uri)
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            userinfo = parsed.username or ""
            if userinfo:
                userinfo = f"{userinfo}@"
            return f"{parsed.scheme}://{userinfo}{netloc}{parsed.path}"
        except Exception:
            return "***"

    default_db = _normalized_database_uri()
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "devkey"),
        SQLALCHEMY_DATABASE_URI=default_db,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", False),
        REMEMBER_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", False),
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
        UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", "/data/uploads"),
        SECURITY_PASSWORD_SALT=os.environ.get("SECURITY_PASSWORD_SALT", "salty"),
        REMEMBER_COOKIE_HTTPONLY=True,
        WTF_CSRF_TIME_LIMIT=None,
        MAIL_SERVER=os.getenv("MAIL_SERVER"),
        MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
        MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
        MAIL_USE_TLS=env_flag("MAIL_USE_TLS", True),
        MAIL_USE_SSL=env_flag("MAIL_USE_SSL", False),
        MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
        MAIL_DEV_LOG_ONLY=env_flag("MAIL_DEV_LOG_ONLY", False),
        APP_BASE_URL=os.getenv("APP_BASE_URL"),
        RESEND_API_KEY=os.getenv("RESEND_API_KEY"),
        RESEND_FROM=os.getenv("RESEND_FROM"),
    )

    if not app.config["SQLALCHEMY_DATABASE_URI"]:
        raise RuntimeError("DATABASE_URL is required for database connectivity")

    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        db_path = app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "", 1)
        if db_path and db_path != ":memory:":
            db_file = Path(db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            app.logger.info("SQLite database path resolved to %s", db_file)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    if app.config["SECRET_KEY"] == "devkey":
        app.logger.warning("SECRET_KEY is using the default value; set a strong secret in the environment")
    if app.config["SECURITY_PASSWORD_SALT"] == "salty":
        app.logger.warning("SECURITY_PASSWORD_SALT is using the default value; set a unique salt in the environment")

    app.logger.info("Database URI in use: %s", _mask_db_uri(app.config["SQLALCHEMY_DATABASE_URI"]))
    app.logger.info("Uploads directory: %s", app.config["UPLOAD_FOLDER"])

    if test_config:
        app.config.update(test_config)

    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    app.jinja_env.globals['csrf_token'] = generate_csrf

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        app.logger.warning("CSRF validation failed on %s from %s: %s", request.path, request.remote_addr, e.description)
        flash("Form expired or invalid. Please try again.", "danger")
        return redirect(request.referrer or url_for("index")), 400

    from .models import User, Report, Discussion, Comment, EmailToken, ModerationLog, ReportImage
    from .security import hash_password, verify_password

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    schema_checked = False
    migration_checked = False

    def check_schema_once():
        nonlocal schema_checked
        if schema_checked:
            return
        inspector = inspect(db.engine)
        required_tables = [
            "user",
            "report",
            "discussion",
            "comment",
            "report_image",
            "email_token",
            "moderation_log",
        ]
        missing = [t for t in required_tables if not inspector.has_table(t)]
        if missing:
            app.logger.error("Database schema missing tables: %s. Run flask db upgrade.", ", ".join(missing))
        schema_checked = True

    def check_migrations_once():
        nonlocal migration_checked
        if migration_checked or app.config.get("TESTING"):
            return
        try:
            from alembic.config import Config
            from alembic.script import ScriptDirectory

            alembic_cfg_path = Path(app.root_path).parent / "migrations" / "alembic.ini"
            if not alembic_cfg_path.exists():
                app.logger.warning("Alembic configuration missing at %s", alembic_cfg_path)
                migration_checked = True
                return
            alembic_cfg = Config(str(alembic_cfg_path))
            script = ScriptDirectory.from_config(alembic_cfg)
            head_rev = script.get_current_head()
            with db.engine.connect() as conn:
                if not conn.dialect.has_table(conn, "alembic_version"):
                    app.logger.error("alembic_version table is missing; run migrations before serving traffic")
                    migration_checked = True
                    return
                current_rev = conn.execute(text("SELECT version_num FROM alembic_version"))
                current_rev = current_rev.scalar()
            if current_rev != head_rev:
                app.logger.error("Database revision %s does not match head %s. Run flask db upgrade.", current_rev, head_rev)
            else:
                app.logger.info("Database migrations are up to date at revision %s", current_rev)
        except Exception:
            app.logger.exception("Migration state check failed")
        migration_checked = True

    @app.before_request
    def _ensure_schema():
        check_schema_once()
        check_migrations_once()

    # simple rate limiting by IP per endpoint
    rate_limits = {}

    def rate_limit(key_func, limit=5, per=60):
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                key = key_func()
                window = datetime.utcnow().replace(second=0, microsecond=0)
                rates = rate_limits.setdefault(key, {})
                if window not in rates:
                    rates.clear()
                    rates[window] = 0
                if rates[window] >= limit:
                    flash("Too many attempts. Please slow down.", "warning")
                    return redirect(request.referrer or url_for("index"))
                rates[window] += 1
                return f(*args, **kwargs)
            return wrapped
        return decorator

    def admin_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(404)
            if not current_user.is_admin:
                abort(404)
            return f(*args, **kwargs)
        return wrapper

    def sanitize_html(html_text):
        allowed_tags = bleach.sanitizer.ALLOWED_TAGS + ["p", "h1", "h2", "h3", "h4", "h5", "h6", "img", "blockquote"]
        allowed_attrs = {"*": ["class", "id", "style"], "a": ["href", "title", "target"], "img": ["src", "alt"]}
        return bleach.clean(html_text, tags=allowed_tags, attributes=allowed_attrs, strip=True)

    def safe_upload_destination(filename: str) -> Path:
        """Ensure uploads remain inside the configured directory."""
        uploads_root = Path(app.config["UPLOAD_FOLDER"]).resolve()
        uploads_root.mkdir(parents=True, exist_ok=True)
        candidate = (uploads_root / filename).resolve()
        if uploads_root != candidate.parent and uploads_root not in candidate.parents:
            app.logger.warning("Blocked upload path traversal attempt: %s", filename)
            abort(400)
        return uploads_root, candidate

    def log_moderation(action, target_type, target_id, reason=None):
        entry = ModerationLog(
            action=action,
            target_type=target_type,
            target_id=target_id,
            actor_id=current_user.id if current_user.is_authenticated else None,
            reason=reason,
            created_at=datetime.utcnow(),
        )
        db.session.add(entry)
        db.session.commit()

    def build_verification_url(token: str) -> str:
        path = url_for("verify_email", token=token, _external=False)
        base_url = app.config.get("APP_BASE_URL")
        if base_url:
            return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            return url_for("verify_email", token=token, _external=True)
        except RuntimeError:
            # Outside request context; fall back to configured base or relative path
            return path

    def send_verification_email(user) -> bool:
        """Send a verification email; return True on success, False on failure."""
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        token = serializer.dumps(user.email, salt=app.config["SECURITY_PASSWORD_SALT"])
        verify_url = build_verification_url(token)

        # store token for validation tracking
        email_token = EmailToken(user_id=user.id, token=token, created_at=datetime.utcnow())
        db.session.add(email_token)
        db.session.commit()

        resend_key = app.config.get("RESEND_API_KEY")
        resend_from = app.config.get("RESEND_FROM") or app.config.get("MAIL_DEFAULT_SENDER") or app.config.get("MAIL_USERNAME")
        mail_server = app.config.get("MAIL_SERVER")
        dev_mailer = app.config.get("MAIL_DEV_LOG_ONLY") or not (resend_key or mail_server)
        sender = resend_from

        if dev_mailer:
            app.logger.info("DEV MAILER: Verification link for %s -> %s", user.email, verify_url)
            return True

        if resend_key:
            try:
                resp = requests.post(
                    "https://api.resend.com/emails",
                    headers={
                        "Authorization": f"Bearer {resend_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "from": sender or "no-reply@casecommons.local",
                        "to": [user.email],
                        "subject": "Verify your Case Commons account",
                        "html": f"<p>Hi {user.username},</p><p>Please verify your account by visiting:<br><a href=\"{verify_url}\">{verify_url}</a></p><p>If you did not sign up, ignore this email.</p>",
                    },
                    timeout=10,
                )
                if resp.ok:
                    app.logger.info("Sent verification email via Resend to %s", user.email)
                    return True
                app.logger.error("Resend API error for %s: status=%s body=%s", user.email, resp.status_code, resp.text)
                return False
            except Exception as exc:
                app.logger.error("Resend call failed for %s: %s", user.email, exc)
                return False

        if not sender or not mail_server:
            app.logger.error("Mail settings incomplete; cannot send verification email to %s", user.email)
            return False

        msg = EmailMessage()
        msg["Subject"] = "Verify your Case Commons account"
        msg["From"] = sender
        msg["To"] = user.email
        msg.set_content(
            f"Hi {user.username},\n\n"
            f"Please verify your account by visiting:\n{verify_url}\n\n"
            "If you did not sign up, ignore this email."
        )
        try:
            if app.config.get("MAIL_USE_SSL"):
                with smtplib.SMTP_SSL(mail_server, app.config["MAIL_PORT"]) as smtp:
                    if app.config.get("MAIL_USERNAME"):
                        smtp.login(app.config["MAIL_USERNAME"], app.config.get("MAIL_PASSWORD"))
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(mail_server, app.config["MAIL_PORT"]) as smtp:
                    if app.config.get("MAIL_USE_TLS"):
                        smtp.starttls()
                    if app.config.get("MAIL_USERNAME"):
                        smtp.login(app.config["MAIL_USERNAME"], app.config.get("MAIL_PASSWORD"))
                    smtp.send_message(msg)
            app.logger.info("Sent verification email via SMTP to %s", user.email)
            return True
        except Exception as exc:
            app.logger.error("Verification email failed for %s: %s", user.email, exc)
            return False

    def verify_token(token, expiration=86400):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
            return email
        except (BadSignature, SignatureExpired):
            return None

    @app.context_processor
    def inject_globals():
        return {"current_year": datetime.utcnow().year}

    @app.route("/")
    def index():
        q = request.args.get('q')
        report_query = Report.query.filter_by(published=True)
        discussion_query = Discussion.query
        if q:
            like = f"%{q}%"
            report_query = report_query.filter(or_(Report.title.ilike(like), Report.body_html.ilike(like)))
            discussion_query = discussion_query.filter(Discussion.title.ilike(like))
        reports = report_query.order_by(Report.created_at.desc()).all()
        discussions = discussion_query.order_by(Discussion.created_at.desc()).limit(5).all()
        return render_template("index.html", reports=reports, discussions=discussions)

    @app.route("/reports/<slug>")
    def report_detail(slug):
        report = Report.query.filter_by(slug=slug, published=True).first_or_404()
        comments = Comment.query.filter_by(parent_type="report", parent_id=report.id).order_by(Comment.created_at.asc()).all()
        return render_template("report_detail.html", report=report, comments=comments)

    @app.route("/discussions")
    def discussions():
        posts = Discussion.query.order_by(Discussion.created_at.desc()).all()
        return render_template("discussions.html", posts=posts)

    @app.route("/discussions/<int:discussion_id>")
    def discussion_detail(discussion_id):
        post = Discussion.query.get_or_404(discussion_id)
        comments = Comment.query.filter_by(parent_type="discussion", parent_id=discussion_id).order_by(Comment.created_at.asc()).all()
        return render_template("discussion_detail.html", post=post, comments=comments)

    @app.route("/register", methods=["GET", "POST"])
    @rate_limit(lambda: f"register:{request.remote_addr}", limit=3, per=60)
    def register():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password")
            if not username or not email or not password:
                flash("All fields are required", "danger")
                return redirect(url_for("register"))
            if User.query.filter((User.username == username) | (func.lower(User.email) == email)).first():
                flash("User already exists", "warning")
                return redirect(url_for("register"))
            user = User(username=username, email=email, password_hash=hash_password(password), email_verified=False, role="user", status="active", created_at=datetime.utcnow())
            db.session.add(user)
            db.session.commit()
            if send_verification_email(user):
                flash("Account created. Check email for verification.", "info")
            else:
                flash("Account created but verification email could not be sent. Please verify mail settings and try resending.", "danger")
            return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/verify/<token>")
    def verify_email(token):
        email = verify_token(token)
        if not email:
            flash("Invalid or expired verification link", "danger")
            return redirect(url_for("login"))
        user = User.query.filter_by(email=email).first_or_404()
        if user.email_verified:
            flash("Email already verified", "info")
        else:
            user.email_verified = True
            db.session.commit()
            flash("Email verified. You may now participate.", "success")
        return redirect(url_for("login"))

    @app.route("/resend-verification", methods=["POST"])
    @login_required
    def resend_verification():
        if current_user.email_verified:
            flash("Email already verified.", "info")
            return redirect(request.referrer or url_for("index"))
        if send_verification_email(current_user):
            flash("Verification email sent.", "success")
        else:
            flash("Could not send verification email. Check mail settings and try again.", "danger")
        return redirect(request.referrer or url_for("index"))

    @app.route("/login", methods=["GET", "POST"])
    @rate_limit(lambda: f"login:{request.remote_addr}", limit=5, per=60)
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password")
            user = User.query.filter((User.username == username) | (User.email == username)).first()
            if not user or not verify_password(password, user.password_hash):
                flash("Invalid credentials", "danger")
                return redirect(url_for("login"))
            if user.status == "banned":
                flash("Your account is banned.", "danger")
                return redirect(url_for("login"))
            session.permanent = True
            login_user(user, remember=True, duration=timedelta(days=30))
            if not user.email_verified:
                flash("Welcome back. Please verify your email to participate fully.", "warning")
            else:
                flash("Welcome back", "success")
            return redirect(url_for("index"))
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Signed out", "info")
        return redirect(url_for("index"))

    def ensure_verified_and_active():
        if current_user.status == "banned":
            logout_user()
            abort(403)
        if not current_user.email_verified:
            flash("Verify your email before participating.", "warning")
            return False
        if current_user.status == "muted":
            flash("You are muted and cannot contribute.", "warning")
            return False
        return True

    @app.route("/comment/<parent_type>/<int:parent_id>", methods=["POST"])
    @login_required
    def add_comment(parent_type, parent_id):
        if parent_type not in {"report", "discussion"}:
            abort(404)
        if not ensure_verified_and_active():
            return redirect(request.referrer or url_for("index"))
        body = request.form.get("body", "").strip()
        if not body:
            flash("Comment cannot be empty", "warning")
            return redirect(request.referrer or url_for("index"))
        comment = Comment(parent_type=parent_type, parent_id=parent_id, body=body, created_by=current_user.id, created_at=datetime.utcnow(), updated_at=datetime.utcnow())
        db.session.add(comment)
        db.session.commit()
        flash("Comment posted", "success")
        return redirect(request.referrer or url_for("index"))

    @app.route("/discussions/new", methods=["GET", "POST"])
    @login_required
    def new_discussion():
        if not ensure_verified_and_active():
            return redirect(url_for("discussions"))
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            if not title or not body:
                flash("Title and body required", "warning")
                return redirect(url_for("new_discussion"))
            post = Discussion(title=title, body=body, created_by=current_user.id, created_at=datetime.utcnow(), updated_at=datetime.utcnow())
            db.session.add(post)
            db.session.commit()
            flash("Discussion created", "success")
            return redirect(url_for("discussion_detail", discussion_id=post.id))
        return render_template("discussion_new.html")

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename):
        if ".." in filename or filename.startswith(("/", "\\")):
            abort(404)
        # ensure filename stays exact (no implicit normalization)
        if secure_filename(filename) != filename:
            abort(404)
        record = ReportImage.query.filter_by(file_path=filename).first()
        if not record:
            abort(404)
        uploads_root, target = safe_upload_destination(filename)
        if not target.exists():
            abort(404)
        return send_from_directory(str(uploads_root), filename)

    @app.route("/admin")
    @login_required
    @admin_required
    def admin_index():
        reports = Report.query.order_by(Report.created_at.desc()).all()
        users = User.query.order_by(User.created_at.desc()).all()
        discussions = Discussion.query.order_by(Discussion.created_at.desc()).all()
        return render_template("admin/index.html", reports=reports, users=users, discussions=discussions)

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_user_new():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password")
            role = request.form.get("role", "user")
            status = request.form.get("status", "active")
            verified = bool(request.form.get("email_verified"))
            if not username or not email or not password:
                flash("Username, email, and password are required", "warning")
                return redirect(url_for("admin_user_new"))
            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("User already exists", "danger")
                return redirect(url_for("admin_user_new"))
            user = User(
                username=username,
                email=email,
                password_hash=hash_password(password),
                role=role,
                status=status,
                email_verified=verified,
                created_at=datetime.utcnow(),
            )
            db.session.add(user)
            db.session.commit()
            log_moderation("create_user", "user", user.id, reason="admin created user")
            flash("User created", "success")
            return redirect(url_for("admin_index"))
        return render_template("admin/user_form.html")

    @app.route("/admin/reports/new", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_report_new():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = sanitize_html(request.form.get("body", ""))
            published = bool(request.form.get("published"))
            if not title:
                flash("Title is required", "warning")
                return redirect(url_for("admin_report_new"))
            slug = "-".join(title.lower().split()) + str(uuid.uuid4())[:6]
            report = Report(title=title, slug=slug, body_html=body, created_by=current_user.id, updated_by=current_user.id, created_at=datetime.utcnow(), updated_at=datetime.utcnow(), published=published)
            db.session.add(report)
            db.session.commit()
            log_moderation("create_report", "report", report.id, request.form.get("reason"))
            flash("Report created", "success")
            return redirect(url_for("admin_index"))
        return render_template("admin/report_form.html", report=None)

    @app.route("/admin/reports/<int:report_id>/edit", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_report_edit(report_id):
        report = Report.query.get_or_404(report_id)
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = sanitize_html(request.form.get("body", ""))
            published = bool(request.form.get("published"))
            if not title:
                flash("Title is required", "warning")
                return redirect(url_for("admin_report_edit", report_id=report.id))
            report.title = title
            report.body_html = body
            report.published = published
            report.updated_at = datetime.utcnow()
            report.updated_by = current_user.id
            db.session.commit()
            log_moderation("update_report", "report", report.id, request.form.get("reason"))
            flash("Report updated", "success")
            return redirect(url_for("admin_index"))
        return render_template("admin/report_form.html", report=report)

    @app.route("/admin/reports/<int:report_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_report_delete(report_id):
        report = Report.query.get_or_404(report_id)
        db.session.delete(report)
        db.session.commit()
        log_moderation("delete_report", "report", report_id, request.form.get("reason"))
        flash("Report deleted", "info")
        return redirect(url_for("admin_index"))

    @app.route("/admin/discussions/new", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_discussion_new():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            if not title or not body:
                flash("Title and body are required", "warning")
                return redirect(url_for("admin_discussion_new"))
            post = Discussion(title=title, body=body, created_by=current_user.id, created_at=datetime.utcnow(), updated_at=datetime.utcnow())
            db.session.add(post)
            db.session.commit()
            log_moderation("create_discussion", "discussion", post.id, request.form.get("reason"))
            flash("Discussion created", "success")
            return redirect(url_for("admin_index"))
        return render_template("admin/discussion_form.html", discussion=None)

    @app.route("/admin/discussions/<int:discussion_id>/edit", methods=["GET", "POST"])
    @login_required
    @admin_required
    def admin_discussion_edit(discussion_id):
        discussion = Discussion.query.get_or_404(discussion_id)
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            if not title or not body:
                flash("Title and body are required", "warning")
                return redirect(url_for("admin_discussion_edit", discussion_id=discussion.id))
            discussion.title = title
            discussion.body = body
            discussion.updated_at = datetime.utcnow()
            db.session.commit()
            log_moderation("update_discussion", "discussion", discussion.id, request.form.get("reason"))
            flash("Discussion updated", "success")
            return redirect(url_for("admin_index"))
        return render_template("admin/discussion_form.html", discussion=discussion)

    @app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
    @login_required
    @admin_required
    def admin_user_toggle(user_id):
        user = User.query.get_or_404(user_id)
        action = request.form.get("action")
        if action == "ban":
            user.status = "banned"
        elif action == "unban":
            user.status = "active"
        elif action == "mute":
            user.status = "muted"
        elif action == "unmute":
            user.status = "active"
        elif action == "promote":
            user.role = "admin"
        elif action == "demote":
            user.role = "user"
        db.session.commit()
        log_moderation(action, "user", user.id, request.form.get("reason"))
        flash("User updated", "success")
        return redirect(url_for("admin_index"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_user_delete(user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        log_moderation("delete_user", "user", user_id, request.form.get("reason"))
        flash("User deleted", "info")
        return redirect(url_for("admin_index"))

    @app.route("/admin/discussions/<int:discussion_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_discussion_delete(discussion_id):
        post = Discussion.query.get_or_404(discussion_id)
        db.session.delete(post)
        db.session.commit()
        log_moderation("delete_discussion", "discussion", discussion_id, request.form.get("reason"))
        flash("Discussion removed", "info")
        return redirect(url_for("admin_index"))

    @app.route("/admin/comments/<int:comment_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_comment_delete(comment_id):
        comment = Comment.query.get_or_404(comment_id)
        db.session.delete(comment)
        db.session.commit()
        log_moderation("delete_comment", "comment", comment_id, request.form.get("reason"))
        flash("Comment removed", "info")
        return redirect(url_for("admin_index"))

    @app.route('/admin/upload', methods=['POST'])
    @login_required
    @admin_required
    def admin_upload():
        file = request.files.get('file')
        if not file:
            app.logger.warning("Upload attempt without file from user %s", current_user.id)
            abort(400)
        original_name = secure_filename(file.filename or "")
        if not original_name:
            app.logger.warning("Upload attempt with empty filename from user %s", current_user.id)
            abort(400)
        if "." not in original_name:
            app.logger.warning("Upload attempt missing extension from user %s", current_user.id)
            abort(400)
        ext = original_name.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_IMAGE_EXT:
            app.logger.warning("Upload attempt with disallowed extension '%s' from user %s", ext, current_user.id)
            abort(400)
        mime_type = (file.mimetype or "").lower()
        if mime_type and not mime_type.startswith("image/"):
            app.logger.warning("Upload attempt with non-image mimetype '%s' from user %s", mime_type, current_user.id)
            abort(400)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_UPLOAD_SIZE:
            app.logger.warning("Upload attempt exceeding max size (%s bytes) from user %s", size, current_user.id)
            abort(400)
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        uploads_root, target_path = safe_upload_destination(unique_name)
        file.save(target_path)
        report_id = request.form.get('report_id')
        try:
            report_id = int(report_id) if report_id else None
        except (TypeError, ValueError):
            report_id = None
        record = ReportImage(
            report_id=report_id,
            file_path=unique_name,
            original_name=original_name,
            mime_type=mime_type or None,
            size_bytes=size,
            uploaded_by=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.session.add(record)
        db.session.commit()
        return {"url": url_for('uploaded_file', filename=unique_name)}

    return app
