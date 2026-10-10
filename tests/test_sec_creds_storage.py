# test_sec_creds_storage.py (SEC-CREDS-01)
import os
import stat
import json
import tarfile
import tempfile

def test_thingino_json_file_permissions():
    """
    SEC-CREDS-01.1: /etc/thingino.json must have restrictive permissions if it contains secrets.
    """
    config_path = "/etc/thingino.json"
    if not os.path.exists(config_path):
        return  # Skip if not deployed
    
    st = os.stat(config_path)
    mode = stat.filemode(st.st_mode)
    
    # Check if readable by non-root
    other_read = bool(st.st_mode & stat.S_IROTH)
    group_read = bool(st.st_mode & stat.S_IRGRP)
    
    assert not other_read and not group_read, \
        f"Config file readable by non-root (mode={mode}): {config_path}"

def test_thingino_json_contents_not_plaintext_secrets():
    """
    SEC-CREDS-01.2: /etc/thingino.json must not store API keys/passwords in plaintext.
    """
    config_path = "/etc/thingino.json"
    if not os.path.exists(config_path):
        return
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except Exception:
        return
    
    # Check for plaintext credentials
    config_str = json.dumps(config).lower()
    dangerous_keys = ["api_key", "bot_token", "password", "secret", "token"]
    dangerous_patterns = [
        "thingino:",  # default RTSP creds
        "root:root",  # default password plaintext
    ]
    
    for key in dangerous_keys:
        assert key not in config_str or config.get(key, "").startswith("$"), \
            f"Plaintext '{key}' found in config: {config}"
    
    for pattern in dangerous_patterns:
        assert pattern not in config_str, \
            f"Dangerous plaintext pattern '{pattern}' in config"

def test_api_key_file_permissions():
    """
    SEC-CREDS-01.3: /etc/thingino-api.key must be mode 600 (root-only).
    """
    api_key_path = "/etc/thingino-api.key"
    if not os.path.exists(api_key_path):
        return
    
    st = os.stat(api_key_path)
    mode_octal = oct(stat.S_IMODE(st.st_mode))
    
    # Must be 0o600
    assert stat.S_IMODE(st.st_mode) == 0o600, \
        f"API key file has insecure permissions (mode={mode_octal}): {api_key_path}"

def test_api_key_not_in_error_logs():
    """
    SEC-CREDS-01.4: API key must not appear in error logs or debug output.
    """
    log_paths = [
        "/var/log/messages",
        "/var/log/httpd.log",
        "/tmp/*.log"
    ]
    
    for pattern in log_paths:
        import glob
        for log_path in glob.glob(pattern):
            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    log_content = f.read()
            except Exception:
                continue
            
            # Read API key
            try:
                with open("/etc/thingino-api.key", "r") as f:
                    api_key = f.read().strip()
            except Exception:
                return
            
            assert api_key not in log_content, \
                f"API key leaked in log file: {log_path}"

def test_backup_archive_not_world_readable():
    """
    SEC-CREDS-01.5: Backup archives must not be world-readable if containing credentials.
    """
    backup_dir = "/tmp/backups"
    if not os.path.isdir(backup_dir):
        return
    
    for backup_file in os.listdir(backup_dir):
        if backup_file.endswith((".tar.gz", ".zip", ".tar")):
            backup_path = os.path.join(backup_dir, backup_file)
            st = os.stat(backup_path)
            other_read = bool(st.st_mode & stat.S_IROTH)
            
            assert not other_read, \
                f"Backup archive world-readable: {backup_path}"
