"""
migrate_add_user_fields.py — one-off migration.

Adds the email, is_admin, reset_token, and reset_token_expires columns to
the existing `users` table WITHOUT touching any scan/finding data. Safe to
run multiple times (skips columns that already exist).

Run once, from the Platform/ directory, with the app NOT running:
    python3 migrate_add_user_fields.py
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ancscan.db")


def column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cur.fetchall())


def main():
    if not os.path.exists(DB_PATH):
        print(f"[!] {DB_PATH} not found — nothing to migrate. A fresh database "
              f"with the new schema will be created automatically the next "
              f"time app.py runs.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    additions = [
        ("email", "VARCHAR(200)"),
        ("is_admin", "BOOLEAN DEFAULT 0"),
        ("reset_token", "VARCHAR(64)"),
        ("reset_token_expires", "DATETIME"),
    ]

    for col, coltype in additions:
        if column_exists(cur, "users", col):
            print(f"[*] Column users.{col} already exists — skipping.")
        else:
            print(f"[*] Adding column users.{col} ...")
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {coltype}")

    # Existing rows won't have is_admin backfilled reliably by the ALTER
    # TABLE default on every SQLite version, so set it explicitly for the
    # original seeded admin account.
    cur.execute("UPDATE users SET is_admin = 1 WHERE username = 'admin'")
    print("[*] Flagged 'admin' as is_admin = 1.")

    conn.commit()
    conn.close()
    print("[*] Migration complete. Your existing scans and findings are untouched.")


if __name__ == "__main__":
    main()
