import pytest
from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

@pytest.fixture
def app():
    app = create_app({'TESTING': True, 'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'})
    with app.app_context():
        db.create_all()
        admin = User(username='admin', email='a@a.com', password_hash=generate_password_hash('pass'), email_verified=True, role='admin', status='active')
        muted = User(username='muted', email='m@m.com', password_hash=generate_password_hash('pass'), email_verified=True, role='user', status='muted')
        banned = User(username='banned', email='b@b.com', password_hash=generate_password_hash('pass'), email_verified=True, role='user', status='banned')
        db.session.add_all([admin, muted, banned])
        db.session.commit()
    yield app
    with app.app_context():
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
