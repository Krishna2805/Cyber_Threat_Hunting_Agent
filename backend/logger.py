import sqlite3

DB_path = "C:\pythonprog\cyber-detection-agent(backend)\data\logs.sqlite"
def log_event(event_type, method, endpoint, username, ip, status_code, status):

    conn = sqlite3.connect(DB_path)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs
        (event_type, method, endpoint, username, ip, status_code, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        method,
        endpoint,
        username,
        ip,
        status_code,
        status
    ))

    conn.commit()
    conn.close()