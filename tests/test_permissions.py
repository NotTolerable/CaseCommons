from app.models import Discussion, Comment, ModerationLog, User
from app.security import hash_password
from app import db


def login(client, username, password='pass'):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)


def test_admin_panel_requires_admin(client):
    login(client, 'admin')
    resp = client.get('/admin')
    assert resp.status_code == 200
    login(client, 'muted')
    resp = client.get('/admin')
    assert resp.status_code == 404


def test_muted_cannot_post_comment(app, client):
    login(client, 'muted')
    with app.app_context():
        d = Discussion(title='t', body='b', created_by=1)
        db.session.add(d)
        db.session.commit()
        disc_id = d.id
    resp = client.post(f'/comment/discussion/{disc_id}', data={'body': 'hello'}, follow_redirects=True)
    assert b'muted' in resp.data


def test_banned_cannot_login(client):
    resp = login(client, 'banned')
    assert b'banned' in resp.data


def test_moderation_log_created_on_action(app, client):
    with app.app_context():
        target = User(username='target', email='t@t.com', password_hash=hash_password('pass'), email_verified=True, role='user', status='active')
        db.session.add(target)
        db.session.commit()
        target_id = target.id
    login(client, 'admin')
    client.post(f'/admin/users/{target_id}/toggle', data={'action': 'ban'}, follow_redirects=True)
    with app.app_context():
        entry = ModerationLog.query.filter_by(target_id=target_id, action='ban').first()
        assert entry is not None


def test_login_succeeds_first_try(client):
    resp = client.post('/login', data={'username': 'admin', 'password': 'pass'}, follow_redirects=True)
    assert b'Welcome back' in resp.data
    assert b'Hi, admin' in resp.data


def test_session_persists_between_pages(client):
    client.post('/login', data={'username': 'admin', 'password': 'pass'}, follow_redirects=True)
    resp = client.get('/discussions')
    assert b'Hi, admin' in resp.data
    assert b'Discussions' in resp.data


def test_create_discussion_when_logged_in(client):
    client.post('/login', data={'username': 'admin', 'password': 'pass'}, follow_redirects=True)
    resp = client.post('/discussions/new', data={'title': 'Test Topic', 'body': 'Body text'}, follow_redirects=True)
    assert b'Discussion created' in resp.data
    assert b'Test Topic' in resp.data


def test_invalid_credentials_message_not_stacked(client):
    resp = client.post('/login', data={'username': 'admin', 'password': 'wrong'}, follow_redirects=True)
    assert resp.data.count(b'Invalid credentials') == 1


def test_application_submission_and_admin_approval(app, client):
    # submit application
    resp = client.post('/apply', data={'full_name': 'New User', 'email': 'new@example.com', 'statement': 'I study law'}, follow_redirects=True)
    assert b'Application submitted' in resp.data
    # approve as admin
    login(client, 'admin')
    with app.app_context():
        app_entry = db.session.execute(db.select(User).where(User.email == 'new@example.com')).scalar_one_or_none()
        assert app_entry is None
    # fetch application id
    from app.models import AccountApplication
    with app.app_context():
        application = AccountApplication.query.filter_by(email='new@example.com').first()
        app_id = application.id
    resp = client.post(f'/admin/applications/{app_id}/approve', data={'username': 'newuser', 'password': 'temp'}, follow_redirects=True)
    assert b'Account created' in resp.data
    # new user can log in
    resp = client.post('/login', data={'username': 'newuser', 'password': 'temp'}, follow_redirects=True)
    assert b'Welcome back' in resp.data
