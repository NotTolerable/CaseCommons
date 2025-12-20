import os
import tempfile
from app import create_app, db
from app.models import Report


def test_persistence_across_app_instances():
    db_fd, db_path = tempfile.mkstemp()
    uri = f"sqlite:///{db_path}"
    app1 = create_app({'SQLALCHEMY_DATABASE_URI': uri, 'TESTING': True})
    with app1.app_context():
        db.create_all()
        r = Report(title='Persist', slug='persist', body_html='x', created_by=None, updated_by=None, published=True)
        db.session.add(r)
        db.session.commit()
        stored_id = r.id
    app2 = create_app({'SQLALCHEMY_DATABASE_URI': uri, 'TESTING': True})
    with app2.app_context():
        found = Report.query.get(stored_id)
        assert found is not None
    os.close(db_fd)
    os.remove(db_path)
