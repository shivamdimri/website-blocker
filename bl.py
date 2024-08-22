import time
from datetime import datetime as dt
from tkinter import *
from tkinter import messagebox
import threading
import os
import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import re

# Path to the hosts file
hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
# Redirect URL
redirect = "127.0.0.1"

# Global variable to track the blocking thread
blocking_thread = None

# Global variable to store the logged-in user's information
logged_in_user = None

# Function to create a new database connection
def create_db_connection():
    conn = sqlite3.connect('website_blocker.db')
    return conn

# Ensure the database and tables are created
def setup_database():
    conn = create_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_websites (website TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS unblocked_websites (website TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS history (website TEXT, action TEXT, timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (name TEXT, username TEXT UNIQUE, password TEXT)''')

    
    c.execute("PRAGMA table_info(history)")
    columns = [column[1] for column in c.fetchall()]
    if 'user' not in columns:
        c.execute('ALTER TABLE history ADD COLUMN user TEXT')

    conn.commit()
    conn.close()

setup_database()


def get_blocked_websites():
    conn = create_db_connection()
    c = conn.cursor()
    c.execute('SELECT website FROM blocked_websites')
    websites = c.fetchall()
    conn.close()
    return [website[0] for website in websites]

def block_websites():
    while True:
        start_hour = 0
        end_hour = 23
        current_time = dt.now()

        try:
            if dt(current_time.year, current_time.month, current_time.day, start_hour) < current_time < dt(current_time.year, current_time.month, current_time.day, end_hour):
                print("Working hours: Blocking websites")
                with open(hosts_path, 'r+') as file:
                    content = file.readlines()
                    existing_blocked_websites = get_blocked_websites()
                    for website in existing_blocked_websites:
                        if website not in content:
                            file.write(f"{redirect} {website}\n")
                            print(f"Blocked {website}")
                flush_dns()
            else:
                print("Non-working hours: Unblocking websites")
                with open(hosts_path, 'r+') as file:
                    content = file.readlines()
                    file.seek(0)
                    for line in content:
                        if not any(website in line for website in get_blocked_websites()):
                            file.write(line)
                    file.truncate()
                flush_dns()
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(10)

def flush_dns():
    try:
        os.system('ipconfig /flushdns')
        print("DNS cache flushed successfully.")
    except Exception as e:
        print(f"Failed to flush DNS cache: {e}")

def start_blocking():
    global blocking_thread

    websites = websites_text.get("1.0", "end-1c").strip()
    website_list = [website.strip() for website in websites.split(",")]

    if website_list:
        conn = create_db_connection()
        c = conn.cursor()

        # Check for duplicates before inserting
        existing_websites = get_blocked_websites()
        for website in website_list:
            if website not in existing_websites:
                c.execute('INSERT INTO blocked_websites (website) VALUES (?)', (website,))
                c.execute('INSERT INTO history (website, action, timestamp, user) VALUES (?, ?, ?, ?)', 
                          (website, 'blocked', dt.now().strftime('%Y-%m-%d %H:%M:%S'), logged_in_user))
        
        conn.commit()
        conn.close()

        if blocking_thread is None or not blocking_thread.is_alive():
            blocking_thread = threading.Thread(target=block_websites, daemon=True)
            blocking_thread.start()
            user_status_label.config(text="Blocking started...", fg="green")
        else:
            user_status_label.config(text="Blocking is already running.", fg="green")
    else:
        user_status_label.config(text="Please enter at least one website.", fg="red")

def unblock_websites_from_admin():
    websites = unblock_websites_text.get("1.0", "end-1c").strip()
    website_list_to_unblock = [website.strip() for website in websites.split(",")]
    if website_list_to_unblock:
        try:
            conn = create_db_connection()
            c = conn.cursor()
            for website in website_list_to_unblock:
                c.execute('DELETE FROM blocked_websites WHERE website=?', (website,))
                c.execute('INSERT INTO unblocked_websites (website) VALUES (?)', (website,))
                c.execute('INSERT INTO history (website, action, timestamp, user) VALUES (?, ?, ?, ?)', 
                          (website, 'unblocked', dt.now().strftime('%Y-%m-%d %H:%M:%S'), 'admin'))
            conn.commit()
            conn.close()
            unblock_websites_in_hosts(website_list_to_unblock)
            flush_dns()
            admin_status_label.config(text="Websites unblocked successfully.", fg="green")
        except Exception as e:
            admin_status_label.config(text=f"Error: {e}", fg="red")
    else:
        admin_status_label.config(text="Please enter at least one website to unblock.", fg="red")

def unblock_websites_in_hosts(website_list_to_unblock):
    try:
        with open(hosts_path, 'r+') as file:
            content = file.readlines()
            file.seek(0)
            for line in content:
                if not any(website in line for website in website_list_to_unblock):
                    file.write(line)
            file.truncate()
    except Exception as e:
        print(f"Error: {e}")

def generate_report():
    try:
        conn = create_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM history ORDER BY timestamp DESC')
        history = c.fetchall()
        conn.close()

        if history:
            report_path = "Website_History_Report.pdf"
            doc = SimpleDocTemplate(report_path, pagesize=letter)
            styles = getSampleStyleSheet()
            data = [['Website', 'Action', 'Timestamp', 'User']]
            for entry in history:
                data.append([entry[0], entry[1], entry[2], entry[3]])

            table = Table(data)
            table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                       ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                       ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                       ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                       ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                       ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                       ('GRID', (0, 0), (-1, -1), 1, colors.black)]))

            doc.build([table])
            report_text.delete("1.0", "end")
            report_text.insert("1.0", f"Report generated successfully: {report_path}")
        else:
            report_text.delete("1.0", "end")
            report_text.insert("1.0", "No history found.")
    except Exception as e:
        admin_status_label.config(text=f"Error: {e}", fg="red")

def open_admin_panel():
    def check_credentials():
        username = username_entry.get()
        password = password_entry.get()
        if username == "admin" and password == "admin":  
            login_window.destroy()
            show_admin_panel()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    login_window = Toplevel(root)
    login_window.geometry('350x250')
    login_window.title("Admin Login")
    login_window.config(bg='lightgrey')

    Label(login_window, text='Username:', font='arial 12', bg='lightgrey').pack(pady=10)
    username_entry = Entry(login_window, font='arial 12')
    username_entry.pack(pady=5)

    Label(login_window, text='Password:', font='arial 12', bg='lightgrey').pack(pady=10)
    password_entry = Entry(login_window, font='arial 12', show='*')
    password_entry.pack(pady=5)

    login_button = Button(login_window, text='Login', font='arial 12 bold', pady=10, command=check_credentials, width=15, bg='green', fg='white', activebackground='sky blue', cursor='hand2')
    login_button.pack(pady=20)

def show_admin_panel():
    def logout_admin():
        admin_window.destroy()
        root.deiconify()  

    admin_window = Toplevel(root)
    admin_window.geometry('600x600')
    admin_window.title('Admin Panel')
    admin_window.config(bg='lightgrey')

    Label(admin_window, text='Unblock Websites:', font='arial 12 bold', bg='lightgrey').pack(pady=10)
    global unblock_websites_text
    unblock_websites_text = Text(admin_window, font='arial 10', height=2, width=50)
    unblock_websites_text.pack(pady=5)

    unblock_button = Button(admin_window, text='Unblock', font='arial 12 bold', pady=5, command=unblock_websites_from_admin, width=15, bg='green', activebackground='LightGreen', cursor='hand2')
    unblock_button.pack(pady=20)

    Label(admin_window, text='Generate History Report:', font='arial 12 bold', bg='lightgrey').pack(pady=10)
    generate_report_button = Button(admin_window, text='Generate Report', font='arial 12 bold', pady=5, command=generate_report, width=15, bg='green', activebackground='LightGreen', cursor='hand2')
    generate_report_button.pack(pady=20)

    global report_text
    report_text = Text(admin_window, font='arial 10', height=2, width=50)
    report_text.pack(pady=5)

    global admin_status_label
    admin_status_label = Label(admin_window, text='', font='arial 12', bg='lightgrey')
    admin_status_label.pack(pady=10)

    logout_button = Button(admin_window, text='Logout', font='arial 12 bold', pady=5, command=logout_admin, width=15, bg='red', fg='white', activebackground='lightcoral', cursor='hand2')
    logout_button.pack(pady=20)

def show_user_panel():
    def logout_user():
        user_window.destroy()
        root.deiconify()  # Show the main window again

    user_window = Toplevel(root)
    user_window.geometry('500x400')
    user_window.title('User Panel')
    user_window.config(bg='lightgrey')

    Label(user_window, text='Enter websites to block (comma separated):', font='arial 12 bold', bg='lightgrey').pack(pady=10)
    global websites_text
    websites_text = Text(user_window, font='arial 10', height=2, width=50)
    websites_text.pack(pady=5)

    block_button = Button(user_window, text='Block', font='arial 12 bold', pady=5, command=start_blocking, width=15, bg='red', fg='white', activebackground='yellow', cursor='hand2')
    block_button.pack(pady=20)

    global user_status_label
    user_status_label = Label(user_window, text='', font='arial 12', bg='lightgrey')
    user_status_label.pack(pady=10)

    logout_button = Button(user_window, text='Logout', font='arial 12 bold', pady=5, command=logout_user, width=15, bg='red', fg='white', activebackground='lightcoral', cursor='hand2')
    logout_button.pack(pady=20)

def register_user():
    def save_user():
        name = name_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()

        if not name or not username or not password:
            messagebox.showerror("Error", "All fields are required!")
            return
        
        if not re.match("^[A-Za-z\\s]+$", name):
            messagebox.showerror("Error", "Name can only contain letters and spaces!")
            return

        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return
        
        if not any(char.isdigit() for char in password):
            messagebox.showerror("Error", "Password must contain at least one number!")
            return
        
        if not any(char.isalpha() for char in password):
            messagebox.showerror("Error", "Password must contain at least one letter!")
            return
        
        if not any(char in '!@#$%^&*()-_=+[]{}|;:",.<>?/~`' for char in password):
            messagebox.showerror("Error", "Password must contain at least one special character!")
            return


        conn = create_db_connection()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (name, username, password) VALUES (?, ?, ?)', (name, username, password))
            conn.commit()
            messagebox.showinfo("Success", "Registration successful!")
            registration_window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")
        finally:
            conn.close()

    registration_window = Toplevel(root)
    registration_window.geometry('350x350')
    registration_window.title("User Registration")
    registration_window.config(bg='lightgrey')

    Label(registration_window, text='Name:', font='arial 12', bg='lightgrey').pack(pady=10)
    name_entry = Entry(registration_window, font='arial 12')
    name_entry.pack(pady=5)

    Label(registration_window, text='Username:', font='arial 12', bg='lightgrey').pack(pady=10)
    username_entry = Entry(registration_window, font='arial 12')
    username_entry.pack(pady=5)

    Label(registration_window, text='Password:', font='arial 12', bg='lightgrey').pack(pady=10)
    password_entry = Entry(registration_window, font='arial 12', show='*')
    password_entry.pack(pady=5)

    save_button = Button(registration_window, text='Register', font='arial 12 bold', pady=10, command=save_user, width=15, bg='royal blue1', activebackground='sky blue', cursor='hand2')
    save_button.pack(pady=20)


def user_login():
    def check_credentials():
        global logged_in_user
        username = username_entry.get()
        password = password_entry.get()
        conn = create_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            logged_in_user = username
            login_window.destroy()
            show_user_panel()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    login_window = Toplevel(root)
    login_window.geometry('350x250')
    login_window.title("User Login")
    login_window.config(bg='lightgrey')

    Label(login_window, text='Username:', font='arial 12', bg='lightgrey').pack(pady=10)
    username_entry = Entry(login_window, font='arial 12')
    username_entry.pack(pady=5)

    Label(login_window, text='Password:', font='arial 12', bg='lightgrey').pack(pady=10)
    password_entry = Entry(login_window, font='arial 12', show='*')
    password_entry.pack(pady=5)

    login_button = Button(login_window, text='Login', font='arial 12 bold', pady=10, command=check_credentials, width=15, bg='green', activebackground='LightGreen', cursor='hand2')
    login_button.pack(pady=20)

root = Tk()
root.geometry('500x400')
root.title('SiteBlocK KING')
root.config(bg='#e27f6a')

Label(root, text='The SiteBlocKING', font='arial 28 bold', bg='red', fg='white').pack(pady=20)

register_button = Button(root, text='Register', font='arial 12 bold', pady=10, command=register_user, width=15, bg='sky blue', activebackground='DarkTurquoise', cursor='hand2')
register_button.pack(pady=10)

login_frame = Frame(root, bg='#e27f6a')
login_frame.pack(pady=20)

admin_login_button = Button(login_frame, text='Admin Login', font='arial 12 bold', pady=10, command=open_admin_panel, width=15, bg='green', fg='white', activebackground='LightGreen', cursor='hand2')
admin_login_button.grid(row=0, column=0, padx=10)

user_login_button = Button(login_frame, text='User Login', font='arial 12 bold', pady=10, command=user_login, width=15, bg='green', fg='white', activebackground='LightGreen', cursor='hand2')
user_login_button.grid(row=0, column=1, padx=10)

root.mainloop()
