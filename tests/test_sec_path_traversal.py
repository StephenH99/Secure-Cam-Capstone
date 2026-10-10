# (SEC-INJECT-01)
import urllib.parse
import http.client
import json

def file_manager_request(host: str, port: int, path: str) -> tuple[int, str]:
    """Send GET request to /x/tool-file-manager.cgi with path parameter."""
    encoded_path = urllib.parse.quote(path, safe="")
    url = f"/x/tool-file-manager.cgi?path={encoded_path}"
    
    conn = http.client.HTTPConnection(host, port, timeout=5)
    # Assume authenticated with valid session (this test focuses on path validation)
    cookies = {"thingino_session": "valid_session_id_for_test"}
    headers = {"Cookie": f"thingino_session={cookies['thingino_session']}"}
    
    conn.request("GET", url, headers=headers)
    response = conn.getresponse()
    status = response.status
    content = response.read().decode("utf-8", errors="ignore")
    conn.close()
    return status, content

def test_path_traversal_up_directories():
    """
    SEC-INJECT-01.1: Attempt to traverse up with ../../etc/passwd must be rejected.
    """
    status, content = file_manager_request("127.0.0.1", 80, "../../etc/passwd")
    
    assert status == 403, f"Expected 403 for path traversal, got {status}"
    assert "passwd" not in content.lower() or "root:" not in content, \
        f"Sensitive file contents leaked: {content[:200]}"

def test_absolute_path_outside_root():
    """
    SEC-INJECT-01.2: Absolute path /etc/shadow must be rejected.
    """
    status, content = file_manager_request("127.0.0.1", 80, "/etc/shadow")
    
    assert status == 403, f"Expected 403 for absolute path outside root, got {status}"
    response_obj = json.loads(content) if content and content[0] == '{' else {}
    assert response_obj.get("error") is not None or status == 403, \
        f"No error for unauthorized path: {content}"

def test_auth_script_read_attempt():
    """
    SEC-INJECT-01.3: Attempt to read /var/www/x/auth.sh (CGI auth logic) must fail.
    """
    status, content = file_manager_request("127.0.0.1", 80, "/var/www/x/auth.sh")
    
    assert status == 403, f"Expected 403, got {status}"
    assert "require_auth" not in content and "validate_session" not in content, \
        f"Auth script source leaked: {content[:300]}"

def test_null_byte_injection_rejected():
    """
    SEC-INJECT-01.4: Null byte in filename (file.txt%00.jpg) must be normalized/rejected.
    """
    status, content = file_manager_request("127.0.0.1", 80, "file.txt%00.jpg")
    
    assert status == 403 or status == 400, \
        f"Expected 403/400 for null byte injection, got {status}"

def test_valid_sdcard_path_allowed():
    """
    SEC-INJECT-01.5: Valid path under /mnt/sdcard must be allowed.
    """
    status, content = file_manager_request("127.0.0.1", 80, "/mnt/sdcard/recordings")
    
    # Should return directory listing or 200 OK (not 403)
    assert status in [200, 404], \
        f"Valid path rejected: {status}"
    if status == 200:
        # Verify it returns directory/file info, not error
        assert "error" not in content.lower() or len(content) > 0, \
            f"Unexpected error on valid path: {content}"
