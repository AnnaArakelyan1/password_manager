import tkinter as tk
from tkinter import messagebox, simpledialog
from encryption import derive_key, encrypt, decrypt
from storage import PasswordStorage
from auth import verify_master_password, set_master_password, master_password_exists
from utils import check_password_strength
from auto_logout import AutoLogout

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.storage = PasswordStorage()
        self.key = None
        # self.auto_logout = AutoLogout(50, self.logout)
        self.auto_logout = AutoLogout(30, lambda: self.logout(force_quit=True)) 
        self.login_screen()

    def login_screen(self):
        self.clear_screen()

        if not master_password_exists():
            pw = simpledialog.askstring("Set Master Password",
                                        "Create a master password:",
                                        show='*')
            if not pw or not check_password_strength(pw):
                messagebox.showerror("Weak Password",
                                     "Master password must be at least 8 characters and include uppercase, lowercase, digit, and special character.")
                self.root.destroy()
                return
            set_master_password(pw)
            messagebox.showinfo("Success", "Master password set. Please login.")
        
        self.label = tk.Label(self.root, text="Enter Master Password:")
        self.label.pack(pady=10)
        self.pw_entry = tk.Entry(self.root, show='*')
        self.pw_entry.pack()
        self.pw_entry.focus_set()

        self.login_btn = tk.Button(self.root, text="Login", command=self.check_login)
        self.login_btn.pack(pady=10)

    def check_login(self):
     pw = self.pw_entry.get()
     if verify_master_password(pw):
        self.key = derive_key(pw)
        self.storage.open_connection() 
        self.main_screen()
     else:
        messagebox.showerror("Error", "Incorrect master password")
        self.pw_entry.delete(0, tk.END)


    def main_screen(self):
        self.clear_screen()
        self.auto_logout.reset_timer()

        self.root.bind_all('<Any-KeyPress>', lambda e: self.auto_logout.reset_timer())
        self.root.bind_all('<Any-Button>', lambda e: self.auto_logout.reset_timer())


        add_frame = tk.Frame(self.root)
        add_frame.pack(pady=10)

        tk.Label(add_frame, text="Service:").grid(row=0, column=0, padx=5, pady=2)
        self.service_entry = tk.Entry(add_frame)
        self.service_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(add_frame, text="Username:").grid(row=1, column=0, padx=5, pady=2)
        self.username_entry = tk.Entry(add_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=2)

        tk.Label(add_frame, text="Password:").grid(row=2, column=0, padx=5, pady=2)
        self.password_entry = tk.Entry(add_frame, show='*')
        self.password_entry.grid(row=2, column=1, padx=5, pady=2)

        self.add_btn = tk.Button(add_frame, text="Add Password", command=self.add_password)
        self.add_btn.grid(row=3, column=0, columnspan=2, pady=5)


        self.list_frame = tk.Frame(self.root)
        self.list_frame.pack(pady=10, fill='both', expand=True)

        self.password_listbox = tk.Listbox(self.list_frame, width=50)
        self.password_listbox.pack(side='left', fill='both', expand=True)
        self.password_listbox.bind('<<ListboxSelect>>', self.show_password_details)

        scrollbar = tk.Scrollbar(self.list_frame, orient='vertical')
        scrollbar.config(command=self.password_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.password_listbox.config(yscrollcommand=scrollbar.set)


        self.details_frame = tk.Frame(self.root)
        self.details_frame.pack(pady=10)

        self.details_text = tk.Text(self.details_frame, width=50, height=5, state='disabled')
        self.details_text.pack()

        self.delete_btn = tk.Button(self.root, text="Delete Selected Password", command=self.delete_password)
        self.delete_btn.pack(pady=5)

        self.logout_btn = tk.Button(self.root, text="Logout", command=self.logout)
        self.logout_btn.pack(pady=5)

        self.refresh_password_list()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def add_password(self):
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not service or not password:
            messagebox.showerror("Error", "Service and password are required")
            return
        if not check_password_strength(password):
            messagebox.showerror("Weak Password",
                                 "Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.")
            return

        encrypted = encrypt(password, self.key)
        self.storage.add_password(service, username, encrypted)

        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.refresh_password_list()
        messagebox.showinfo("Success", "Password added successfully")

    def refresh_password_list(self):
        self.password_listbox.delete(0, tk.END)
        self.entries = self.storage.get_all_passwords()
        for entry in self.entries:
            self.password_listbox.insert(tk.END, f"{entry[1]} ({entry[2]})")

        self.details_text.configure(state='normal')
        self.details_text.delete('1.0', tk.END)
        self.details_text.configure(state='disabled')

    def show_password_details(self, event):
        self.auto_logout.reset_timer()
        selection = self.password_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        entry = self.entries[index]
        try:
            decrypted_password = decrypt(entry[3], self.key)
        except Exception:
            decrypted_password = "Error decrypting"

        self.details_text.configure(state='normal')
        self.details_text.delete('1.0', tk.END)
        self.details_text.insert(tk.END,
                                 f"Service: {entry[1]}\nUsername: {entry[2]}\nPassword: {decrypted_password}")
        self.details_text.configure(state='disabled')

    def delete_password(self):
        self.auto_logout.reset_timer()
        selection = self.password_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No password selected to delete")
            return
        index = selection[0]
        entry_id = self.entries[index][0]
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?")
        if confirm:
            self.storage.delete_password(entry_id)
            self.refresh_password_list()

    def logout(self, force_quit=False):
     self.auto_logout.stop_timer()
     self.key = None
     self.storage.close()
     if force_quit:
        messagebox.showinfo("Auto Logout", "You have been logged out due to inactivity.")
        self.root.destroy()
     else:
        self.login_screen()


if __name__ == '__main__':
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
