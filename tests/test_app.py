import pytest
from app import create_app, db, User, Feedback

@pytest.fixture()
def app(tmp_path):
    app=create_app({"TESTING":True,"WTF_CSRF_ENABLED":False,"SQLALCHEMY_DATABASE_URI":"sqlite:///:memory:","SECRET_KEY":"test"})
    with app.app_context(): db.create_all()
    return app

@pytest.fixture()
def client(app): return app.test_client()

def register(client,email="student@example.com"):
    return client.post("/register",data={"full_name":"Test Student","email":email,"password":"StrongPass8","confirm_password":"StrongPass8"},follow_redirects=True)

def login(client,email="student@example.com"):
    return client.post("/login",data={"email":email,"password":"StrongPass8"},follow_redirects=True)

def test_registration_hashes_password(app,client):
    response=register(client); assert b"Account created successfully" in response.data
    with app.app_context():
        user=db.session.execute(db.select(User)).scalar_one(); assert user.password_hash != "StrongPass8"

def test_duplicate_registration(client):
    register(client); response=register(client); assert b"already exists" in response.data

def test_login_required(client):
    response=client.get("/add-feedback",follow_redirects=True); assert b"Please log in" in response.data

def test_login_save_and_public_view(app,client):
    register(client); login(client)
    response=client.post("/feedback",data={"subject":"DBMS","work_type":"Project","deadline":"2030-01-02","difficulty":"Medium","stress":"High","feedback":"Need more lab time."},follow_redirects=True)
    assert b"Feedback saved successfully" in response.data
    client.post("/logout")
    response=client.get("/view-feedback"); assert b"DBMS" in response.data and b"Need more lab time" in response.data
    with app.app_context(): assert db.session.query(Feedback).count()==1

def test_invalid_dropdown_rejected(client):
    register(client); login(client)
    response=client.post("/feedback",data={"subject":"DBMS","work_type":"Hacked","deadline":"2030-01-02","difficulty":"Medium","stress":"High","feedback":"Test"},follow_redirects=True)
    assert b"valid information" in response.data

def test_malformed_password_hash_never_causes_500(app,client):
    with app.app_context():
        db.session.add(User(full_name="Broken Account",email="broken@example.com",password_hash="$damaged")); db.session.commit()
    response=client.post("/login",data={"email":"broken@example.com","password":"StrongPass8"},follow_redirects=True)
    assert response.status_code==200 and b"incorrect" in response.data

def test_registration_repairs_unusable_account(app,client):
    with app.app_context():
        db.session.add(User(full_name="Broken Account",email="repair@example.com",password_hash="$damaged")); db.session.commit()
    response=register(client,"repair@example.com")
    assert b"repaired successfully" in response.data
    response=login(client,"repair@example.com")
    assert b"Save Feedback" in response.data
