from app.models import Discussion, Comment
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
