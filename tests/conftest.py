import os
import sys

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.security import hash_password
from app import create_app, db
from app.models import User

@pytest.fixture
def upload_dir(tmp_path):
    path = tmp_path / "uploads"
    path.mkdir()
    return path


@pytest.fixture
def app(upload_dir):
    app = create_app({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': False,
        'UPLOAD_FOLDER': str(upload_dir),
    })
    with app.app_context():
        db.create_all()
        admin = User(username='admin', email='a@a.com', password_hash=hash_password('pass'), email_verified=True, role='admin', status='active')
        muted = User(username='muted', email='m@m.com', password_hash=hash_password('pass'), email_verified=True, role='user', status='muted')
        banned = User(username='banned', email='b@b.com', password_hash=hash_password('pass'), email_verified=True, role='user', status='banned')
        db.session.add_all([admin, muted, banned])
        db.session.commit()
    yield app
    with app.app_context():
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
