import getpass
from dotenv import load_dotenv
from database import get_db_connection
from auth import hash_password

load_dotenv()

def create_user(username, password, role):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM users WHERE username = %s",(username,))
        existing = cursor.fetchone()

        hashed = hash_password(password)

        if existing:
            cursor.execute("UPDATE users SET password_hash=%s, role = %s WHERE username = %s", (hashed, role, username))
            print(f"\n User '{username}' updated successfully with role '{role}'.")
        else:
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (username, hashed, role))
            print(f"\n User '{username}' created successfully with role '{role}'.")
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()

def main():
    print("\n=== Sentinel Gateway — User Management ===\n")

    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return
    
    password = getpass.getpass("Enter password: ")
    if len(password) < 6:
        print("Error: Password must be at least 6 characters.")
        return

    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: Passwords do not match.")
        return

    print("Select role:")
    print(" 1. User")
    print(" 2. Admin")
    choice = input("Enter 1 or 2 [default: 1]: ").strip()
    role = "Admin" if choice == "2" else "User"

    create_user(username, password, role)

if __name__ == "__main__":
    main()