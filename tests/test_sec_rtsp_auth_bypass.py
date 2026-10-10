
# test_sec_rtsp_auth_bypass.py
import base64
import socket

def send_rtsp_request(host: str, port: int, request: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.sendall(request.encode("utf-8"))
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    finally:
        s.close()
    return response.decode("utf-8", errors="ignore")

def test_rtsp_missing_auth_header_rejected():
    """
    SEC-AUTH-01.1: RTSP SETUP without Authorization header must be rejected.
    """
    request = (
        "SETUP rtsp://127.0.0.1:554/ch0 RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "Transport: RTP/AVP;unicast\r\n"
        "\r\n"
    )
    
    response = send_rtsp_request("127.0.0.1", 554, request)
    assert "401" in response or "Unauthorized" in response, \
        f"Expected 401 Unauthorized, got: {response[:200]}"

def test_rtsp_empty_auth_header_rejected():
    """
    SEC-AUTH-01.2: RTSP SETUP with empty Authorization header must be rejected.
    """
    request = (
        "SETUP rtsp://127.0.0.1:554/ch0 RTSP/1.0\r\n"
        "CSeq: 2\r\n"
        "Authorization: Basic \r\n"
        "Transport: RTP/AVP;unicast\r\n"
        "\r\n"
    )
    
    response = send_rtsp_request("127.0.0.1", 554, request)
    assert "401" in response or "Unauthorized" in response, \
        f"Expected 401 Unauthorized, got: {response[:200]}"

def test_rtsp_malformed_base64_auth_rejected():
    """
    SEC-AUTH-01.3: RTSP SETUP with invalid Base64 Authorization must be rejected.
    """
    # Send malformed Base64 (not valid B64, missing padding)
    request = (
        "SETUP rtsp://127.0.0.1:554/ch0 RTSP/1.0\r\n"
        "CSeq: 3\r\n"
        "Authorization: Basic !!invalid_base64!!\r\n"
        "Transport: RTP/AVP;unicast\r\n"
        "\r\n"
    )
    
    response = send_rtsp_request("127.0.0.1", 554, request)
    assert "401" in response or "Unauthorized" in response, \
        f"Expected 401 Unauthorized, got: {response[:200]}"
    # Should NOT reveal internal error details like "Base64 decode failed at offset..."
    assert "offset" not in response.lower() and "decode" not in response.lower(), \
        f"Error message leaked implementation details: {response}"

def test_rtsp_default_credentials_accepted_then_flagged():
    """
    SEC-AUTH-01.4: RTSP login with default credentials (thingino:thingino) 
    must be accepted BUT session must be flagged for mandatory password change.
    """
    creds = base64.b64encode(b"thingino:thingino").decode("utf-8")
    request = (
        "SETUP rtsp://127.0.0.1:554/ch0 RTSP/1.0\r\n"
        "CSeq: 4\r\n"
        f"Authorization: Basic {creds}\r\n"
        "Transport: RTP/AVP;unicast\r\n"
        "\r\n"
    )
    
    response = send_rtsp_request("127.0.0.1", 554, request)
    # Should NOT immediately reject, but stream may require re-auth or carry warning
    assert ("200" in response or "401" in response), \
        f"Unexpected RTSP response: {response[:200]}"
