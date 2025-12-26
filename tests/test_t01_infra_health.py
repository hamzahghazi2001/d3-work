import socket
import requests

def test_t01_health_ok():
    r = requests.get("http://localhost:5000/health", timeout=5)
    assert r.status_code == 200
    assert r.json().get("status") == "ok"

def test_t01_deps_ok_and_schema_present():
    r = requests.get("http://localhost:5000/health/deps", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert data["db_ok"] is True
    assert data["redis_ok"] is True
    assert data["required_tables_present"] is True
    assert data["missing_tables"] == []

def test_t01_mailpit_ports_reachable():
    # SMTP port
    with socket.create_connection(("mailpit", 1025), timeout=5):
        pass
    # UI port
    r = requests.get("http://mailpit:8025/", timeout=5)
    assert r.status_code == 200
