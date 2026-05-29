import re
import html
from urllib.parse import unquote

# --- SQLi Patterns ---
# These match common SQL Injection attack strings
SQLI_PATTERNS = [
    r"(\s|'|\")(or|and)\s+[\w'\"]+\s*=\s*[\w'\"]+",     #' OR 1=1, ' AND 1=1
    r"union\s+(all\s+)?select",                         # UNION SELECT
    r"--\s*$",                                          # SQL comment --
    r"/\*.*?\*/",                                       # SQL comment /* */
    r";\s*(drop|delete|insert|update)",                 # Stacked queries
    r"(sleep|benchmark|waitfor)\s*\(",                  # Time-based blind SQLi
    r"select\s+.*\s+.*\s+from\s",                       # SELECT ... FROM (basic query)
    r"insert\s+into\s+\w+",                             # INSERT INTO
    r"information_schema",                              # DB enumeration
    r"xp_cmdshell",                                     # SQL Server command execution
    r"into\s(outfile|dumpfile)",                        # MySQL file write
    r"order\s+by\s+\d+",                                # Column count enumeration
]

# --- XSS Patterns ---
# These match common Cross-Site Scripting attack strings
XSS_PATTERNS = [
    r"<\s*script.*?>",                                  # <script> tags
    r"javascript\s*:",                                  # javascript: protocol
    r"on(click|load|error|mouseover|submit|focus|blur|keydown|keyup|resize|scroll)\s*=",   # onerror="...", onload="..."
    r"<\s*iframe.*?>",                                  # <iframe> injection
    r"data\s*:\s*text/html",                            # data: URI scheme
    r"<\s*img[^>]+onerror\s*=",                         # <img onerror= ...>
    r"<\s*svg[^>]+onload\s*=",                          # <svg onload= ...>
    r"document\s*\.\s*cookie",                          # Cookie theft
    r"eval\s*\(",                                       # eval() execution
    r"String\.fromCharCode",                            # Character encoding bypass
]

# --- Path Traversal Patterns ---
# These match common directory traversal attack strings
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",                           # ../
    r"\.\.\\",                          # ..\
    r"%2e%2e",                          # %2e%2e (URL encoded)
    r"etc/passwd",                      # Linux user account info
    r"etc/shadow",                      # Linux password hashes
    r"windows/system32",                # Windows system directory
    r"proc/self/environ",               # Linux environment variables
]

# Pre-compile all patterns once at startup for performance
# re.IGNORECASE means these work regardless of uppercase/lowercase
COMPILED_SQLI = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in SQLI_PATTERNS]
COMPILED_XSS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in XSS_PATTERNS]
COMPILED_PATH = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in PATH_TRAVERSAL_PATTERNS]

def _normalize(data: str) -> str:
    """
    Decodes URL encoding twice to catch double-encoded bypass attempts.
    e.g. %2527 -> %27 -> ' (single pass decoders miss this entirely).
    Lowercased so patterns don't need to account for case variants.
    """
    decoded = unquote(unquote(data))
    decoded = html.unescape(decoded)
    decoded = decoded.replace('\x00', '')
    return decoded.lower()

def inspect_request(data: str) -> dict:
    """
    Inspects a string (from URI, headers, or body) for attack patterns.
    Input is normalized (double URL-decoded, lowercased) before scanning to prevent encoding-based WAF bypass attempts.
    Returns a dict: {"is_malicious": bool, "attack_type": str or None}
    """
    normalized = _normalize(data)
    for pattern in COMPILED_SQLI:
        if pattern.search(normalized):
            return {"is_malicious": True, "attack_type": "SQL Injection"}

    for pattern in COMPILED_XSS:
        if pattern.search(normalized):
            return {"is_malicious": True, "attack_type": "XSS"}
    
    for pattern in COMPILED_PATH:
        if pattern.search(normalized):
            return {"is_malicious": True, "attack_type": "Path Traversal"}

    return {"is_malicious": False, "attack_type": None}

def inspect_json_body(body: dict) -> dict:
    """
    Inspects a JSON body for attack patterns.
    Recursively checks all values in the JSON object.
    """
    for key, value in body.items():
        if isinstance(value, str):
            result = inspect_request(value)
            if result["is_malicious"]:
                return result
        elif isinstance(value, dict):
            result = inspect_json_body(value)
            if result["is_malicious"]:
                return result
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    result = inspect_request(item)
                    if result["is_malicious"]:
                        return result
                elif isinstance(item, dict):
                    result = inspect_json_body(item)
                    if result["is_malicious"]:
                        return result
    return {"is_malicious": False, "attack_type": None}
