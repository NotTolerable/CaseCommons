import os
from datetime import datetime
from app import create_app, db
from app.models import User, Report, Discussion, Comment
from werkzeug.security import generate_password_hash

app = create_app()
app.app_context().push()

def seed():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', password_hash=generate_password_hash('password'), email_verified=True, role='admin', status='active')
        muted = User(username='muted', email='muted@example.com', password_hash=generate_password_hash('password'), email_verified=True, role='user', status='muted')
        banned = User(username='banned', email='banned@example.com', password_hash=generate_password_hash('password'), email_verified=True, role='user', status='banned')
        user = User(username='user', email='user@example.com', password_hash=generate_password_hash('password'), email_verified=True, role='user', status='active')
        db.session.add_all([admin, muted, banned, user])
        db.session.commit()
    admin = User.query.filter_by(username='admin').first()
    if not Report.query.first():
        r1 = Report(title='Landmark Contract Case', slug='landmark-contract', body_html='<p>Analysis of contract principles.</p>', created_by=admin.id, updated_by=admin.id, published=True)
        r2 = Report(title='Tort Reform Overview', slug='tort-reform', body_html='<p>Tort reforms and implications.</p>', created_by=admin.id, updated_by=admin.id, published=True)
        db.session.add_all([r1, r2])
        db.session.commit()
    if not Discussion.query.first():
        d1 = Discussion(title='Thoughts on consideration', body='How is consideration evolving?', created_by=admin.id)
        d2 = Discussion(title='Public policy defenses', body='Where should courts draw the line?', created_by=admin.id)
        db.session.add_all([d1, d2])
        db.session.commit()
        c1 = Comment(parent_type='discussion', parent_id=d1.id, body='Great topic!', created_by=admin.id)
        db.session.add(c1)
        db.session.commit()
    print('Seed data ready')

if __name__ == '__main__':
    seed()
