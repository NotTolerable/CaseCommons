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


def test_unverified_cannot_post_discussion(app, client):
    with app.app_context():
        pending = User(username='pending', email='p@p.com', password_hash=hash_password('pass'), email_verified=False, role='user', status='active')
        db.session.add(pending)
        db.session.commit()
    login(client, 'pending')
    resp = client.post('/discussions/new', data={'title': 't', 'body': 'b'}, follow_redirects=True)
    assert b'Verify your email' in resp.data


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
