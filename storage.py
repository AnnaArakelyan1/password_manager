import sqlite3

class PasswordStorage:
    def __init__(self, db_path="passwords.db"):
        self.db_path = db_path
        self.conn = None
        self.open_connection()
        self._create_table()

    def open_connection(self):
        if self.conn is None:
            self.conn = sqlite3.connect("passwords.db", check_same_thread=False)

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def _create_table(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      service TEXT NOT NULL,
                      username TEXT,
                      password TEXT NOT NULL)''')
        self.conn.commit()

    def add_password(self, service, username, encrypted_password):
        c = self.conn.cursor()
        c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                  (service, username, encrypted_password))
        self.conn.commit()

    def get_all_passwords(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM passwords")
        return c.fetchall()

    def delete_password(self, entry_id):
        c = self.conn.cursor()
        c.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        self.conn.commit()

    def update_password(self, entry_id, new_encrypted_password):
     c = self.conn.cursor()
     c.execute("UPDATE passwords SET password = ? WHERE id = ?", (new_encrypted_password, entry_id))
     self.conn.commit()
