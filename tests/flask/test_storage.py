import pytest
import tempfile
import shutil
from pathlib import Path
from aiwaf.flask.storage import (
    is_ip_allowlisted, add_ip_allowlist,
    is_ip_blocklisted, add_ip_blocklist, remove_ip_blocklist,
    add_keyword, get_top_keywords,
    add_geo_blocked_country, remove_geo_blocked_country,
    is_country_geo_blocked, get_geo_blocked_countries
)
from aiwaf.flask.db_models import BlocklistedIP

def test_add_ip_allowlist(app_context):
    """Test adding IP to allowlist."""
    ip = '192.168.1.1'
    assert not is_ip_allowlisted(ip)
    
    add_ip_allowlist(ip)
    assert is_ip_allowlisted(ip)

def test_add_duplicate_ip_allowlist(app_context):
    """Test adding duplicate IP to allowlist."""
    ip = '192.168.1.1'
    add_ip_allowlist(ip)
    add_ip_allowlist(ip)  # Should not raise error
    assert is_ip_allowlisted(ip)

def test_add_ip_blocklist(app_context):
    """Test adding IP to blocklist."""
    ip = '10.0.0.1'
    reason = 'suspicious activity'
    assert not is_ip_blocklisted(ip)
    
    add_ip_blocklist(ip, reason)
    assert is_ip_blocklisted(ip)

    entry = BlocklistedIP.query.filter_by(ip=ip).first()
    assert entry is not None
    assert entry.reason == reason
    assert entry.reputation_reason.startswith(reason)
    assert entry.score == 10
    assert entry.offenses == 1
    assert entry.expires_at > entry.blocked_at

def test_remove_ip_blocklist(app_context):
    """Test removing IP from blocklist."""
    ip = '10.0.0.1'
    add_ip_blocklist(ip, 'test')
    assert is_ip_blocklisted(ip)
    
    remove_ip_blocklist(ip)
    assert not is_ip_blocklisted(ip)

def test_remove_nonexistent_ip_blocklist(app_context):
    """Test removing non-existent IP from blocklist."""
    ip = '10.0.0.1'
    remove_ip_blocklist(ip)  # Should not raise error
    assert not is_ip_blocklisted(ip)

def test_add_keyword(app_context):
    """Test adding keyword."""
    keyword = 'malicious'
    add_keyword(keyword)
    keywords = get_top_keywords()
    assert keyword in keywords

def test_add_duplicate_keyword(app_context):
    """Test adding duplicate keyword."""
    keyword = 'malicious'
    add_keyword(keyword)
    add_keyword(keyword)  # Should not raise error
    keywords = get_top_keywords()
    assert keyword in keywords

def test_get_top_keywords(app_context):
    """Test getting top keywords."""
    keywords = ['kw1', 'kw2', 'kw3']
    for kw in keywords:
        add_keyword(kw)
    
    top_keywords = get_top_keywords(2)
    assert len(top_keywords) == 2
    for kw in top_keywords:
        assert kw in keywords

def test_geo_blocked_countries_db(app_context):
    """Test geo blocked countries in database storage."""
    country = 'US'
    assert not is_country_geo_blocked(country)

    add_geo_blocked_country(country)
    assert is_country_geo_blocked(country)
    assert country in get_geo_blocked_countries()

    remove_geo_blocked_country(country)
    assert not is_country_geo_blocked(country)

# CSV-specific tests
@pytest.fixture
def csv_app():
    """Create Flask app configured for CSV storage."""
    from flask import Flask
    
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['AIWAF_USE_CSV'] = True
    
    # Create temporary directory for CSV files
    temp_dir = tempfile.mkdtemp()
    app.config['AIWAF_DATA_DIR'] = temp_dir
    
    yield app
    
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def csv_app_context(csv_app):
    """Create application context for CSV storage."""
    with csv_app.app_context():
        yield csv_app

def test_csv_storage_allowlist(csv_app_context):
    """Test CSV storage for allowlist operations."""
    ip = '192.168.100.1'
    
    # Test add and check
    add_ip_allowlist(ip)
    assert is_ip_allowlisted(ip)

def test_csv_storage_blocklist(csv_app_context):
    """Test CSV storage for blocklist operations."""
    ip = '10.10.10.1'
    reason = 'CSV test'
    
    # Test add and check
    add_ip_blocklist(ip, reason)
    assert is_ip_blocklisted(ip)
    
    # Test removal
    remove_ip_blocklist(ip)
    assert not is_ip_blocklisted(ip)


def test_csv_storage_blocklist_extended_request_info_column(csv_app_context):
    ip = "10.10.10.2"
    add_ip_blocklist(ip, "CSV extended", extended_request_info={"path": "/login"})

    csv_file = Path(csv_app_context.config["AIWAF_DATA_DIR"]) / "blacklist.csv"
    content = csv_file.read_text(encoding="utf-8")
    header = content.splitlines()[0]
    assert "extended_request_info" in header


def test_csv_storage_blocklist_reputation_metadata(csv_app_context):
    from aiwaf.flask.storage import _read_csv_blocklist

    ip = "10.10.10.3"
    add_ip_blocklist(ip, "scanner", extended_request_info={"path": "/scan"})

    entry = _read_csv_blocklist()[ip]
    assert entry["reason"] == "scanner"
    assert entry["score"] == 20
    assert entry["offenses"] == 1
    assert entry["expires_at"] > entry["blocked_at"]
    assert entry["extended_request_info"] == {"path": "/scan"}

def test_csv_storage_keywords(csv_app_context):
    """Test CSV storage for keywords."""
    keyword = 'csv_test_keyword'
    
    # Test add and check
    add_keyword(keyword)
    keywords = get_top_keywords()
    assert keyword in keywords

def test_csv_storage_geo_blocked_countries(csv_app_context):
    """Test CSV storage for geo blocked countries."""
    country = 'FR'

    add_geo_blocked_country(country)
    assert is_country_geo_blocked(country)
    assert country in get_geo_blocked_countries()

    remove_geo_blocked_country(country)
    assert not is_country_geo_blocked(country)
def test_csv_blocklist_and_allowlist_helpers(tmp_path, monkeypatch):
    from aiwaf.flask import storage

    monkeypatch.setenv("AIWAF_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(storage, "_get_storage_mode", lambda: "csv")
    storage._append_csv_blocklist("203.0.113.100", "test", {"path": "/"})
    storage.add_ip_allowlist("203.0.113.101")
    storage.remove_ip_allowlist("203.0.113.101")
    storage._rewrite_csv_allowlist({"203.0.113.102"})
    assert "203.0.113.102" in storage._read_csv_allowlist()

    exemptions = storage.ExemptionStore()
    exemptions.add_exempt("203.0.113.103")
    assert exemptions.is_exempted("203.0.113.103")
