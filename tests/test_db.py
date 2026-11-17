from secureqr import db
from secureqr.core.analyzer import analyze_payload
from tests.test_analyzer import FakePredictor


def test_insert_list_get_delete(app):
    with app.app_context():
        ids = [db.insert_scan("url", analyze_payload(u, FakePredictor(p)))
               for u, p in [("https://good.example", 0.01), ("http://203.0.113.5/login", 0.99)]]
        items, total = db.list_scans()
        assert total == 2 and items[0]["id"] == ids[1]  # newest first
        assert db.list_scans(risk="HIGH")[1] == 1
        assert db.list_scans(query="good.example")[1] == 1
        assert db.list_scans(query="%")[1] == 0          # LIKE wildcards escaped
        full = db.get_scan(ids[0])
        assert full["result"]["url"] == "https://good.example"
        assert db.delete_scan(ids[0]) and db.get_scan(ids[0]) is None
        assert db.clear_scans() == 1 and db.list_scans()[1] == 0


def test_sql_injection_strings_are_data(app):
    with app.app_context():
        evil = "https://x.example/'); DROP TABLE scans; --"
        db.insert_scan("url", analyze_payload(evil, FakePredictor(0.5)))
        assert db.list_scans(query="' OR 1=1 --")[1] == 0
        assert db.list_scans()[1] == 1  # table still exists
        assert db.get_scan(1)["raw_content"] == evil


def test_stats(app):
    with app.app_context():
        db.insert_scan("upload", analyze_payload("http://198.51.100.1/a", FakePredictor(0.9)))
        db.insert_scan("webcam", analyze_payload("https://ok.example", FakePredictor(0.1)))
        s = db.stats()
        assert s["total"] == 2
        assert s["by_source"]["upload"] == 1 and s["by_source"]["webcam"] == 1
        assert sum(d["LOW"] + d["MEDIUM"] + d["HIGH"] for d in s["daily"]) == 2
        assert len(s["daily"]) == 14
        assert any(f["id"] == "ip_host" for f in s["top_findings"])
