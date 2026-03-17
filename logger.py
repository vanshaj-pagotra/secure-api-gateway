from database import get_db_connection

def log_event(event_type: str, source_ip: str, details: str):
    """
    Inserts a security event into the security_logs table.
    Called whenever the gateway block a request or detects an attack.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_logs (event_type, source_ip, details)
            VALUES (%s, %s, %s)
            """,
            (event_type, source_ip, details)
        )
        conn.commit()
    except Exception as e:
        print(f"[LOGGER ERROR] Failed to log event: {e}")
    finally:
        if 'conn' in locals() and conn:
            cursor.close()
            conn.close()