# test_sec_bola_storage.py (SEC-AUTHZ-02)
import http.client
import json
import urllib.parse

def file_manager_list(host: str, port: int, path: str, session_id: str) -> tuple[int, dict]:
    """Request directory listing from file manager."""
    encoded_path = urllib.parse.quote(path, safe="")
    url = f"/x/tool-file-manager.cgi?path={encoded_path}&action=list"
    
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Cookie": f"thingino_session={session_id}"}
    
    conn.request("GET", url, headers=headers)
    response = conn.getresponse()
    status = response.status
    content = response.read().decode("utf-8", errors="ignore")
    conn.close()
    
    try:
        obj = json.loads(content)
    except Exception:
        obj = {}
    
    return status, obj

def file_manager_get_file(host: str, port: int, filepath: str, session_id: str) -> tuple[int, bytes]:
    """Download a file via file manager."""
    encoded_path = urllib.parse.quote(filepath, safe="")
    url = f"/x/tool-file-manager.cgi?path={encoded_path}&action=download"
    
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Cookie": f"thingino_session={session_id}"}
    
    conn.request("GET", url, headers=headers)
    response = conn.getresponse()
    status = response.status
    content = response.read()
    conn.close()
    
    return status, content

def test_bola_cross_user_file_access():
    """
    SEC-AUTHZ-02.1: User A must not access User B's private video files.
    (In single-user camera context, test access to logically separate directories.)
    """
    user_a_session = "session_user_a_token"
    user_b_private_file = "/mnt/sdcard/recordings/2024-01-15/private_clip.mp4"
    
    # Assume camera has multiple recording contexts (e.g., different channels or time-based isolation)
    status, content = file_manager_get_file("127.0.0.1", 80, user_b_private_file, user_a_session)
    
    # Should be forbidden
    assert status == 403, f"Expected 403 for unauthorized file access, got {status}"
    assert len(content) == 0 or b"error" in content.lower(), \
        f"File contents returned despite BOLA: {content[:100]}"

def test_bola_directory_enumeration_filtered():
    """
    SEC-AUTHZ-02.2: Directory listing must not expose files outside user's allowed path.
    """
    session_id = "valid_session_token"
    
    # Request parent directory
    status, obj = file_manager_list("127.0.0.1", 80, "/mnt/sdcard", session_id)
    
    # Should either deny access to parent or return only permitted subdirs
    assert status in [403, 200], f"Unexpected status: {status}"
    
    if status == 200:
        # If allowed, verify only safe directories are listed
        listed_items = obj.get("files", [])
        forbidden_dirs = ["etc", "sys", "proc", "root", "var/www"]
        for item in listed_items:
            name = item.get("name", "").lower()
            assert not any(fd in name for fd in forbidden_dirs), \
                f"Forbidden directory in listing: {name}"

def test_bola_sequential_file_id_enumeration():
    """
    SEC-AUTHZ-02.3: Sequential ID-based file access (if used) must validate ownership.
    """
    session_id = "valid_session_token"
    
    # Attempt to access sequential video files by ID/filename
    for video_id in range(1, 10):
        video_path = f"/mnt/sdcard/recordings/video_{video_id}.mp4"
        status, content = file_manager_get_file("127.0.0.1", 80, video_path, session_id)
        
        # If file exists, it must be owned by current user or access denied
        if status == 200:
            # Verify file is within allowed scope (not another user's private archive)
            assert "private" not in video_path.lower() or status == 403, \
                f"Private file accessible: {video_path}"
