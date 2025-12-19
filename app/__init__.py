import os
from flask import Flask, render_template, redirect, url_for, session, flash, request, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta
from functools import wraps
import bleach
from werkzeug.utils import secure_filename
import uuid
from sqlalchemy import or_

# Extensions
csrf = CSRFProtect()
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024


def create_app(test_config=None):
    app = Flask(__name__)

    default_db = os.environ.get(
        "DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/casecommons"
    )
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "devkey"),
        SQLALCHEMY_DATABASE_URI=default_db,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", os.path.join(os.getcwd(), "static", "uploads")),
        SECURITY_PASSWORD_SALT=os.environ.get("SECURITY_PASSWORD_SALT", "salty"),
        REMEMBER_COOKIE_HTTPONLY=True,
        WTF_CSRF_TIME_LIMIT=None,
    )

    if test_config:
        app.config.update(test_config)

    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    app.jinja_env.globals['csrf_token'] = generate_csrf

    from .models import User, Report, Discussion, Comment, EmailToken, ModerationLog, ReportImage

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

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

    def send_verification_email(user):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        token = serializer.dumps(user.email, salt=app.config["SECURITY_PASSWORD_SALT"])
        url = url_for("verify_email", token=token, _external=True)
        # placeholder email sending; log to console
        app.logger.info("Verification email for %s: %s", user.email, url)
        # store token for validation tracking
        email_token = EmailToken(user_id=user.id, token=token, created_at=datetime.utcnow())
        db.session.add(email_token)
        db.session.commit()

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
            username = request.form.get("username").strip()
            email = request.form.get("email").strip().lower()
            password = request.form.get("password")
            if not username or not email or not password:
                flash("All fields are required", "danger")
                return redirect(url_for("register"))
            if User.query.filter((User.username == username) | (User.email == email)).first():
                flash("User already exists", "warning")
                return redirect(url_for("register"))
            user = User(username=username, email=email, password_hash=generate_password_hash(password), email_verified=False, role="user", status="active", created_at=datetime.utcnow())
            db.session.add(user)
            db.session.commit()
            send_verification_email(user)
            flash("Account created. Check email for verification.", "info")
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

    @app.route("/login", methods=["GET", "POST"])
    @rate_limit(lambda: f"login:{request.remote_addr}", limit=5, per=60)
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid credentials", "danger")
                return redirect(url_for("login"))
            if user.status == "banned":
                flash("Your account is banned.", "danger")
                return redirect(url_for("login"))
            login_user(user)
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

    @app.route("/uploads/<filename>")
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.route("/admin")
    @login_required
    @admin_required
    def admin_index():
        reports = Report.query.order_by(Report.created_at.desc()).all()
        users = User.query.order_by(User.created_at.desc()).all()
        discussions = Discussion.query.order_by(Discussion.created_at.desc()).all()
        return render_template("admin/index.html", reports=reports, users=users, discussions=discussions)

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
        flash("Report deleted", "info")
        return redirect(url_for("admin_index"))

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
        db.session.add(ModerationLog(action=action, target_type="user", target_id=user.id, actor_id=current_user.id, created_at=datetime.utcnow(), reason=request.form.get("reason")))
        db.session.commit()
        flash("User updated", "success")
        return redirect(url_for("admin_index"))

    @app.route("/admin/discussions/<int:discussion_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_discussion_delete(discussion_id):
        post = Discussion.query.get_or_404(discussion_id)
        db.session.delete(post)
        db.session.commit()
        flash("Discussion removed", "info")
        return redirect(url_for("admin_index"))

    @app.route("/admin/comments/<int:comment_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def admin_comment_delete(comment_id):
        comment = Comment.query.get_or_404(comment_id)
        db.session.delete(comment)
        db.session.commit()
        flash("Comment removed", "info")
        return redirect(url_for("admin_index"))

    @app.route('/admin/upload', methods=['POST'])
    @login_required
    @admin_required
    def admin_upload():
        file = request.files.get('file')
        if not file:
            abort(400)
        filename = secure_filename(file.filename)
        if not filename:
            abort(400)
        ext = filename.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_IMAGE_EXT:
            abort(400)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_UPLOAD_SIZE:
            abort(400)
        unique_name = f"{uuid.uuid4().hex}.{ext}"
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        path = os.path.join(upload_folder, unique_name)
        file.save(path)
        record = ReportImage(report_id=request.form.get('report_id'), file_path=unique_name, uploaded_by=current_user.id, created_at=datetime.utcnow())
        db.session.add(record)
        db.session.commit()
        return {"url": url_for('uploaded_file', filename=unique_name)}

    return app
