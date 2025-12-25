import io

from app.models import ReportImage


def login_admin(client):
    client.post('/login', data={'username': 'admin', 'password': 'pass'}, follow_redirects=True)


def test_admin_upload_records_metadata_and_serves_file(app, client, upload_dir):
    login_admin(client)
    payload_bytes = b"\x89PNG\r\n\x1a\n"
    payload = io.BytesIO(payload_bytes)
    resp = client.post('/admin/upload', data={'file': (payload, 'test.png')}, content_type='multipart/form-data')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'url' in data
    filename = data['url'].split('/uploads/')[-1]

    with app.app_context():
        record = ReportImage.query.filter_by(file_path=filename).first()
        assert record is not None
        assert record.original_name == 'test.png'
        assert record.mime_type.startswith('image/') if record.mime_type else True
        assert record.size_bytes == len(payload_bytes)

    assert (upload_dir / filename).exists()
    get_resp = client.get(f'/uploads/{filename}')
    assert get_resp.status_code == 200


def test_admin_upload_rejects_bad_extension(client):
    login_admin(client)
    resp = client.post('/admin/upload', data={'file': (io.BytesIO(b'data'), 'bad.txt')}, content_type='multipart/form-data')
    assert resp.status_code == 400


def test_upload_route_blocks_traversal(client):
    login_admin(client)
    resp = client.get('/uploads/../secret')
    assert resp.status_code == 404
