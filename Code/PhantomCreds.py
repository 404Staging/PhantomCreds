import os
import re
import csv
import datetime
import getpass
import win32security
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog
import tkinter.font as tkFont

# Globals
stop_flag = threading.Event()
files_checked = 0
scan_done = threading.Event()

# Functions
def on_entry_click(event, entry_widget, placeholder):
    if entry_widget.get() == placeholder:
        entry_widget.delete(0, tk.END)
        entry_widget.configure(foreground='black')

def on_entry_leave(event, entry_widget, placeholder):
    if entry_widget.get() == '':
        entry_widget.insert(0, placeholder)
        entry_widget.configure(foreground='grey')

def browse_usernames():
    filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if filename:
        entry1.delete(0, tk.END)
        entry1.insert(0, filename)
        entry1.configure(foreground='black')

def browse_directory():
    directory = filedialog.askdirectory()
    if directory:
        entry2.delete(0, tk.END)
        entry2.insert(0, directory)
        entry2.configure(foreground='black')

def browse_output():
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:
        entry3.delete(0, tk.END)
        entry3.insert(0, filename)
        entry3.configure(foreground='black')

def get_file_owner(path):
    try:
        sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
        return f"{domain}\\{name}"
    except Exception:
        return "Unknown"

def log_to_csv_and_gui(file_path, creation_date, owner, filename_match, username_match, password_match, output_csv):
    with open(output_csv, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([file_path, creation_date, owner, filename_match, username_match, password_match])

    message_text.insert(
        tk.END,
        f"{file_path} | Created: {creation_date} | Owner: {owner} | "
        f"FilenameMatch: {filename_match} | UsernameMatch: {username_match} | PasswordMatch: {password_match}\n"
    )
    message_text.see(tk.END)

def update_progress():
    last_count = -1
    while not stop_flag.is_set():
        if scan_done.is_set():
            break
        if files_checked != last_count:
            message_text.insert(tk.END, f"Files checked: {files_checked}\n")
            message_text.see(tk.END)
            last_count = files_checked
        time.sleep(5)

def scan_files(directory_to_scan, usernames_file, output_csv):
    global files_checked

    password_pattern = re.compile(
        r"(?=^[^\s]{12,26}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])(?!^[a-fA-F0-9]{12,26}$)"
    )

    try:
        with open(usernames_file, 'r', encoding='utf-8') as f:
            usernames = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        message_text.insert(tk.END, f"Usernames file not found: {usernames_file}\n")
        usernames = set()

    if not os.path.exists(output_csv):
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["FilePath", "CreationDate", "Owner", "FilenameMatch", "UsernameMatch", "PasswordMatch"])

    for root, dirs, files in os.walk(directory_to_scan):
        for file in files:
            full_path = os.path.join(root, file)
            lower_name = file.lower()
            files_checked += 1

            try:
                creation_time = datetime.datetime.fromtimestamp(os.path.getctime(full_path))
                owner = get_file_owner(full_path)
                filename_match = any(keyword in lower_name for keyword in ['user', 'username', 'password'])
                username_match = False
                password_match = False

                if filename_match:
                    log_to_csv_and_gui(full_path, creation_time, owner, True, False, False, output_csv)
                    continue

                if file.lower().endswith(('.txt', '.log', '.csv', '.conf', '.ini')):
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            username_match = any(username in content for username in usernames)
                            password_match = bool(password_pattern.search(content))
                            if username_match or password_match:
                                log_to_csv_and_gui(full_path, creation_time, owner, False, username_match, password_match, output_csv)
                    except Exception as e:
                        message_text.insert(tk.END, f"Could not read file: {full_path} ({e})\n")
                        message_text.see(tk.END)

            except Exception as e:
                message_text.insert(tk.END, f"Error processing file: {full_path} ({e})\n")
                message_text.see(tk.END)

    scan_done.set()
    message_text.insert(tk.END, f"Hunt complete! Files Scanned: {files_checked}")

    message_text.see(tk.END)
    stop_flag.set()

def threaded_hunt():
    global files_checked
    files_checked = 0
    scan_done.clear()
    directory_to_scan = entry2.get() if entry2.get() != placeholder2 else r"C:\\Temp\\Test"
    usernames_file = entry1.get() if entry1.get() != placeholder1 else r"C:\\Temp\\usernames.txt"
    output_csv = entry3.get() if entry3.get() != placeholder3 else r"C:\\Temp\\hangingcreds.csv"

    stop_flag.clear()
    t1 = threading.Thread(target=scan_files, args=(directory_to_scan, usernames_file, output_csv), daemon=True)
    t2 = threading.Thread(target=update_progress, daemon=True)
    t1.start()
    t2.start()

# GUI 
root = tk.Tk()
root.title("PhantomCreds")
custom_font = tkFont.Font(family="Helvetica", size=16, weight="bold")

# Dark Mode Styling
dark_mode_bg = "#282828"
dark_mode_fg = "white"
dark_mode_entry_bg = "#333333"
dark_mode_entry_fg = "white"
dark_mode_button_bg = "#666666"
dark_mode_button_fg = "black"
dark_mode_label_fg = "white"
dark_mode_message_text_bg = "#222222"
dark_mode_message_text_fg = "white"

style = ttk.Style()
style.configure("TFrame", background=dark_mode_bg)
style.configure("TLabel", foreground=dark_mode_label_fg, background=dark_mode_bg)
style.configure("TButton", foreground=dark_mode_button_fg, background=dark_mode_button_bg)
style.configure("TEntry", foreground=dark_mode_entry_fg, background=dark_mode_entry_bg)
style.configure("TText", foreground=dark_mode_message_text_fg, background=dark_mode_message_text_bg)

frm = ttk.Frame(root, padding=10)
frm.grid()
ttk.Label(frm, text="PhantomCreds", font=custom_font).grid(column=0, row=0, columnspan=2)

placeholder1 = "User Names to look for: 'c:\\temp\\usernames.txt'"
row1_frame = ttk.Frame(frm)
row1_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky='w')
ttk.Button(row1_frame, text="Browse", command=browse_usernames).pack(side=tk.LEFT, padx=(0, 5))
entry1 = ttk.Entry(row1_frame, width=50, foreground='grey')
entry1.insert(0, placeholder1)
entry1.bind("<FocusIn>", lambda event: on_entry_click(event, entry1, placeholder1))
entry1.bind("<FocusOut>", lambda event: on_entry_leave(event, entry1, placeholder1))
entry1.pack(side=tk.LEFT)

placeholder2 = "Directory to scan: 'c:\\temp\\share'"
row2_frame = ttk.Frame(frm)
row2_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky='w')
ttk.Button(row2_frame, text="Browse", command=browse_directory).pack(side=tk.LEFT, padx=(0, 5))
entry2 = ttk.Entry(row2_frame, width=50, foreground='grey')
entry2.insert(0, placeholder2)
entry2.bind("<FocusIn>", lambda event: on_entry_click(event, entry2, placeholder2))
entry2.bind("<FocusOut>", lambda event: on_entry_leave(event, entry2, placeholder2))
entry2.pack(side=tk.LEFT)

placeholder3 = "Location to export findings: 'c:\\temp\\hangingcreds.csv'"
row3_frame = ttk.Frame(frm)
row3_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky='w')
ttk.Button(row3_frame, text="Browse", command=browse_output).pack(side=tk.LEFT, padx=(0, 5))
entry3 = ttk.Entry(row3_frame, width=50, foreground='grey')
entry3.insert(0, placeholder3)
entry3.bind("<FocusIn>", lambda event: on_entry_click(event, entry3, placeholder3))
entry3.bind("<FocusOut>", lambda event: on_entry_leave(event, entry3, placeholder3))
entry3.pack(side=tk.LEFT)

ttk.Button(frm, text="Hunt", command=threaded_hunt, width=7).grid(column=0, row=5, columnspan=2, padx=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
ttk.Button(frm, text="Stop", command=root.destroy, width=7).grid(column=0, row=6, columnspan=2, padx=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))

message_text = tk.Text(frm, wrap=tk.WORD, width=50, height=15, background='grey')
message_text.grid(row=7, column=0, columnspan=2, padx=0, pady=5, sticky="w")

root.mainloop()
stop_flag.set()
