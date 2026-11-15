import builtins
import contextlib
import glob
import io
import os

import customtkinter as ctk
import pandas as pd

import analysis
import collect
import database

ctk.set_appearance_mode("dark")


def collect_data(dbms, version):
    #Run the original collect.fetch_nvd_data()

    os.makedirs("csv_files", exist_ok=True)
    answers = iter([dbms, version, "y"])

    real_input = builtins.input
    builtins.input = lambda prompt="": next(answers, "q")  # "q" = quit if it asks more
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            collect.fetch_nvd_data()
    finally:
        builtins.input = real_input
    lines = output.getvalue().strip().splitlines()
    return lines[-1] if lines else "No output from collect.py"


def say(message, ok=False):
    status.configure(text=message, text_color="lightgreen" if ok else "red")


def show(view):
    for v in (collect_view, analysis_view, connect_view, db_view):
        v.grid_remove()
    view.grid()
    say("")


def run_collect():
    dbms = dbms_entry.get().strip().lower()
    version = version_entry.get().strip()
    if dbms not in ("mongodb", "cassandra") or not version.replace(".", "").isdigit():
        say("Error: enter MongoDB or Cassandra, and a version like 5.0.")
        return
    say("Fetching data from NVD...", ok=True)
    app.update()  # show the message before the request blocks the window
    try:
        message = collect_data(dbms, version)
        say(message, ok=message.startswith("Successfully"))
    except Exception as e:
        say(f"Error: {e}")


def show_analysis():
    for widget in file_list.winfo_children():
        widget.destroy()
    checks.clear()
    for path in sorted(glob.glob("csv_files/*.csv")):
        name = os.path.basename(path)
        box = ctk.CTkCheckBox(file_list, text=name)
        box.pack(anchor="w", pady=2)
        checks[name] = box
    show(analysis_view)


def run_analysis():
    files = [name for name, box in checks.items() if box.get()]
    if not files:
        say("Error: select at least one file.")
        return
    try:
        df = analysis.get_csv_info(files)
    except Exception as e:
        say(f"Error: {e}")
        return
    if df is None:
        say("Error: could not read the selected files.")
        return
    table = df.sort_values("Risk Score", ascending=False).to_string(index=False)
    output_box.delete("1.0", "end")
    output_box.insert("1.0", table)
    say(f"Analyzed {len(files)} file(s).", ok=True)


conn = None


def connect_db():
    global conn
    connect_box.delete("1.0", "end")
    try:
        if conn is None:
            conn = database.connect_to_database()
            connect_box.insert("end", "Connection successful!\n")
            database.create_tables(conn)
            connect_box.insert("end", "Database tables have successfully been created and setup!\n")
        else:
            connect_box.insert("end", "Already connected.\n")
        say(f"Connected to {database.DB_FILE}.", ok=True)
    except Exception as e:
        conn = None
        connect_box.insert("end", f"Database connection error: {e}\n")
        say(f"Error: {e}")


def add_to_database():
    files = [name for name, box in checks.items() if box.get()]
    if not files:
        say("Error: select at least one file.")
        return
    if conn is None:
        say("Error: connect to the database first.")
        return
    try:
        for name in files:
            database.import_csv(conn, "csv_files/" + name)
        say(f"Added {len(files)} file(s) to the database.", ok=True)
    except Exception as e:
        say(f"Error: {e}")


def show_database():
    show(db_view)



app = ctk.CTk()
app.title("DBMS Vulnerability Dashboard")
app.geometry("850x550")
app.grid_columnconfigure(1, weight=1)
app.grid_rowconfigure(0, weight=1)

# Menu
menu = ctk.CTkFrame(app, width=200)
menu.grid(row=0, column=0, rowspan=2, sticky="ns")
ctk.CTkButton(menu, text="1  NVD Data Collection", command=lambda: show(collect_view)).pack(padx=20, pady=(40, 6))
ctk.CTkButton(menu, text="2  Vulnerability Analysis", command=show_analysis).pack(padx=20, pady=6)
ctk.CTkButton(menu, text="3  Connect to Database", command=lambda: show(connect_view)).pack(padx=20, pady=6)
ctk.CTkButton(menu, text="4  View Database", command=show_database).pack(padx=20, pady=6)
ctk.CTkButton(menu, text="5  Exit", command=app.destroy).pack(padx=20, pady=6)


collect_view = ctk.CTkFrame(app)
analysis_view = ctk.CTkFrame(app)
connect_view = ctk.CTkFrame(app)
db_view = ctk.CTkFrame(app)
for view in (collect_view, analysis_view, connect_view, db_view):
    view.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
    view.grid_columnconfigure(0, weight=1)
    view.grid_rowconfigure(0, weight=1)

status = ctk.CTkLabel(app, text="", anchor="w")
status.grid(row=1, column=1, sticky="w", padx=20, pady=(0, 20))

# Option 1
body = ctk.CTkFrame(collect_view, fg_color="transparent")
body.grid(row=0, column=0, sticky="nsew")
ctk.CTkLabel(body, text="DBMS name (MongoDB or Cassandra)").pack(anchor="w", pady=(10, 2))
dbms_entry = ctk.CTkEntry(body, width=300)
dbms_entry.pack(anchor="w")
ctk.CTkLabel(body, text="Version number (e.g. 5.0)").pack(anchor="w", pady=(14, 2))
version_entry = ctk.CTkEntry(body, width=300)
version_entry.pack(anchor="w")
ctk.CTkButton(collect_view, text="Collect Data", command=run_collect).grid(row=1, column=0, sticky="w", pady=10, padx=10)

# Option 2
checks = {}
body = ctk.CTkFrame(analysis_view, fg_color="transparent")
body.grid(row=0, column=0, sticky="nsew")
file_list = ctk.CTkScrollableFrame(body, height=120)
file_list.pack(fill="x", pady=(10, 10))
output_box = ctk.CTkTextbox(body, font=("Courier", 13), wrap="none")
output_box.pack(fill="both", expand=True)
buttons = ctk.CTkFrame(analysis_view, fg_color="transparent")
buttons.grid(row=1, column=0, sticky="w", pady=10, padx=10)
ctk.CTkButton(buttons, text="Run Analysis", command=run_analysis).pack(side="left", padx=(0, 10))
ctk.CTkButton(buttons, text="Add to Database", command=add_to_database).pack(side="left")

# Option 3
connect_box = ctk.CTkTextbox(connect_view, font=("Courier", 13))
connect_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
ctk.CTkButton(connect_view, text="Connect", command=connect_db).grid(row=1, column=0, sticky="w", pady=10, padx=10)

# Option 4
db_box = ctk.CTkTextbox(db_view, font=("Courier", 13), wrap="none")
db_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

show(collect_view)
app.mainloop()