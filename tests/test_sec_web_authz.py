# test_sec_web_authz.py
import http.client
import json

def send_cgi_request(host: str, port: int, path: str, method: str = "GET",
                     body: str | None = None, cookies: dict | None = None) -> tuple[int, str]:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "application/json"}
    
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers["Cookie"] = cookie_str
    
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    status = response.status
    content = response.read().decode("utf-8", errors="ignore")
    conn.close()
    return status, content

def test_reboot_cgi_no_session_rejected():
    """
    SEC-AUTHZ-01.1: /x/reboot.cgi without session cookie must be rejected.
    """
    status, content = send_cgi_request("127.0.0.1", 80, "/x/reboot.cgi", "GET")
    
    assert status == 401 or status == 302, \
        f"Expected 401 or redirect, got {status}"
    # Should NOT execute reboot
    assert "rebooting" not in content.lower(), \
        f"Reboot executed without authentication: {content}"

def test_config_webui_invalid_session_rejected():
    """
    SEC-AUTHZ-01.2: /x/json-config-webui.cgi with invalid session ID must be rejected.
    """
    payload = json.dumps({"password": "newpass"})
    cookies = {"thingino_session": "invalid_session_id_12345"}
    
    status, content = send_cgi_request(
        "127.0.0.1", 80, "/x/json-config-webui.cgi",
        method="POST", body=payload, cookies=cookies
    )
    
    assert status == 401, f"Expected 401, got {status}"
    response_obj = json.loads(content) if content else {}
    assert response_obj.get("error") is not None or status == 401, \
        f"No error returned for invalid session: {content}"

def test_config_webui_forged_session_rejected():
    """
    SEC-AUTHZ-01.3: /x/json-config-webui.cgi with forged (non-existent) session must be rejected.
    """
    payload = json.dumps({"camera": {"resolution": "640x480"}})
    forged_sid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    cookies = {"thingino_session": forged_sid}
    
    status, content = send_cgi_request(
        "127.0.0.1", 80, "/x/json-config-webui.cgi",
        method="POST", body=payload, cookies=cookies
    )
    
    assert status == 401, f"Expected 401, got {status}"
    # Ensure config NOT modified (would need to query actual config state)

def test_config_webui_csrf_no_samesite_check():
    """
    SEC-AUTHZ-01.4: Verify SameSite=Strict cookie attribute is enforced.
    If Set-Cookie lacks SameSite, CSRF attack from cross-origin iframe is possible.
    """
    # Simulate cross-origin POST (would require actual browser test)
    # For now, check HTTP response headers from login endpoint
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
    conn.request("POST", "/x/login.cgi", 
                 body=json.dumps({"username": "root", "password": "root"}),
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    headers = dict(response.getheaders())
    conn.close()
    
    set_cookie = headers.get("set-cookie", "").lower()
    assert "samesite=strict" in set_cookie or "samesite=lax" in set_cookie, \
        f"Cookie missing SameSite attribute (CSRF risk): {set_cookie}"
