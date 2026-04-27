import os
import mysql.connector
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Demo Backend — Intentionally Vulnerable")

def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 3306)),
        database=os.getenv("DB_NAME", "demo_backend_db"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", "")
    )

# ── Book schema for POST body ──
class BookIn(BaseModel):
    title: str
    author: str
    description: str = ""

# ─────────────────────────────────────────
# PUBLIC
# ─────────────────────────────────────────

@app.get("/books")
def get_books():
    """Public: returns all books. No vulnerability here."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM books")
    books = cursor.fetchall()
    conn.close()
    return {"books": books}

@app.get("/books/search")
def search_books(q: str = ""):
    """
    VULNERABLE: query parameter injected directly into SQL.
    Without the gateway WAF, exploitable with: ?q=' OR '1'='1
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    # Intentionally vulnerable — DO NOT use parameterized query here
    query = f"SELECT * FROM books WHERE title LIKE '%{q}%' OR author LIKE '%{q}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return {"results": results, "query": q}

# ─────────────────────────────────────────
# AUTHENTICATED (gateway enforces JWT)
# ─────────────────────────────────────────

@app.get("/books/{book_id}")
def get_book(book_id: int):
    """Returns a single book. Gateway enforces authentication."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM books WHERE id = %s", (book_id,))
    book = cursor.fetchone()
    conn.close()
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    return {"book": book}

@app.get("/profile")
def get_profile():
    """
    VULNERABLE: No auth check internally. Returns user list to anyone.
    The gateway enforces JWT before this is ever reached.
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, email, role, joined FROM demo_users")
    users = cursor.fetchall()
    conn.close()
    for user in users:
        if user.get("joined"):
            user["joined"] = str(user["joined"])
    return {"users": users}

@app.get("/stats")
def get_stats():
    """Returns application statistics. Gateway enforces authentication."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as count FROM books")
    books_count = cursor.fetchone()["count"]
    cursor.execute("SELECT COUNT(*) as count FROM demo_users")
    users_count = cursor.fetchone()["count"]
    conn.close()
    return {
        "total_books": books_count,
        "total_users": users_count,
        "status": "running"
    }

# ─────────────────────────────────────────
# ADMIN ONLY (gateway enforces Admin role)
# ─────────────────────────────────────────

@app.get("/admin/users")
def get_all_users():
    """
    VULNERABLE: No admin check internally. Returns all user data to anyone.
    The gateway enforces Admin JWT before this is ever reached.
    """
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM demo_users")
    users = cursor.fetchall()
    conn.close()
    for user in users:
        if user.get("joined"):
            user["joined"] = str(user["joined"])
    return {"total": len(users), "users": users}

@app.post("/admin/books")
def add_book(book: BookIn):
    """Admin only: add a new book. Gateway enforces Admin JWT."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO books (title, author, description) VALUES (%s, %s, %s)",
        (book.title, book.author, book.description)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return {"message": "Book added successfully", "id": new_id}

@app.delete("/admin/books/{book_id}")
def delete_book(book_id: int):
    """Admin only: delete a book by ID. Gateway enforces Admin JWT."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM books WHERE id = %s", (book_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="Book not found")
    return {"message": f"Book {book_id} deleted"}

# ─────────────────────────────────────────
# SERVE FRONTEND
# ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    """Serves the RBAC demo frontend."""
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())