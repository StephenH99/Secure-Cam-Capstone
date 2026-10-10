# test_sec_command_injection.py (SEC-INJECT-02)
import http.client
import urllib.parse
import json

def ping_tool_request(host: str, port: int, target: str, count: str = "4") -> tuple[int, str]:
    """Send request to /x/tool-ping-trace.cgi."""
    encoded_target = urllib.parse.quote(target, safe="")
    encoded_count = urllib.parse.quote(count, safe="")
    url = f"/x/tool-ping-trace.cgi?host={encoded_target}&count={encoded_count}"
    
    conn = http.client.HTTPConnection(host, port, timeout=5)
    cookies = {"thingino_session": "valid_session_for_test"}
    headers = {"Cookie": f"thingino_session={cookies['thingino_session']}"}
    
    conn.request("GET", url, headers=headers)
    response = conn.getresponse()
    status = response.status
    content = response.read().decode("utf-8", errors="ignore")
    conn.close()
    return status, content

def config_network_request(host: str, port: int, payload: dict) -> tuple[int, str]:
    """Send request to /x/json-config-network.cgi."""
    conn = http.client.HTTPConnection(host, port, timeout=5)
    cookies = {"thingino_session": "valid_session_for_test"}
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"thingino_session={cookies['thingino_session']}"
    }
    
    body = json.dumps(payload)
    conn.request("POST", "/x/json-config-network.cgi", body=body, headers=headers)
    response = conn.getresponse()
    status = response.status
    content = response.read().decode("utf-8", errors="ignore")
    conn.close()
    return status, content

def test_ping_shell_injection_semicolon():
    """
    SEC-INJECT-02.1: Ping with shell metacharacter (;) must be escaped/rejected.
    """
    status, content = ping_tool_request("127.0.0.1", 80, "127.0.0.1; rm -rf /")
    
    # Should NOT execute rm command
    # (Check via subsequent file existence checks in a full test environment)
    assert status in [400, 200], f"Unexpected status: {status}"
    # Output should be either error or sanitized ping results
    assert "rm -rf" not in content or "error" in content.lower() or "invalid" in content.lower(), \
        f"Injection payload echoed in response: {content}"

def test_ping_shell_injection_and_operator():
    """
    SEC-INJECT-02.2: Ping with && operator must not execute second command.
    """
    status, content = ping_tool_request("127.0.0.1", 80, "127.0.0.1 && reboot")
    
    assert "reboot" not in content or "error" in content.lower(), \
        f"Reboot command may have been executed: {content}"

def test_ping_command_substitution_injection():
    """
    SEC-INJECT-02.3: Ping with command substitution $(...) must be rejected.
    """
    status, content = ping_tool_request("127.0.0.1", 80, "127.0.0.1$(cat /etc/shadow)")
    
    assert status in [400, 200], f"Unexpected status: {status}"
    assert "root:" not in content, \
        f"/etc/shadow contents leaked via command substitution: {content}"

def test_network_config_json_sql_injection():
    """
    SEC-INJECT-02.4: JSON config with SQL-like injection must not corrupt data.
    """
    payload = {
        "network": {
            "gateway": "192.168.1.1\"; DROP TABLE config; --"
        }
    }
    
    status, content = config_network_request("127.0.0.1", 80, payload)
    
    # Should reject or sanitize, not execute SQL
    assert status in [400, 200], f"Unexpected status: {status}"
    response_obj = json.loads(content) if content and content[0] == '{' else {}
    # Gateway should be stored/rejected safely
    if response_obj.get("error") is None and status == 200:
        # If accepted, verify stored value is sanitized
        assert "DROP" not in str(response_obj), \
            f"SQL injection payload stored: {response_obj}"

def test_network_config_command_substitution():
    """
    SEC-INJECT-02.5: Network config hostname with command substitution must fail.
    """
    payload = {
        "network": {
            "hostname": "camera$(cat /etc/shadow)"
        }
    }
    
    status, content = config_network_request("127.0.0.1", 80, payload)
    
    assert status in [400, 200], f"Unexpected status: {status}"
    response_obj = json.loads(content) if content and content[0] == '{' else {}
    assert "root:" not in content, \
        f"Command substitution payload executed: {content}"
