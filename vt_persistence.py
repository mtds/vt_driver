#!/usr/bin/env python

import datetime
import os
import sqlite3
import time

def create_Db():
    conn = sqlite3.connect('vt_samples.db')

    # Obj to access the DB
    c = conn.cursor()

    # Create table
    c.execute('''CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY, submitted_date TEXT, hash_sig TEXT, sig_name TEXT)''')

    conn.close()

def check_Db():
    if not os.path.exists('vt_samples.db'):
        create_Db()

def insert_Data(hash_sig, sig_name):
    conn = sqlite3.connect('vt_samples.db')

    # Obj to access the DB
    c = conn.cursor()

    # UNIX Epoch time
    unix_tm = int(time.time())

    # Date+Time
    date = str(datetime.datetime.fromtimestamp(unix_tm).strftime('%Y-%m-%d %H:%M:%S'))

    # Insert data into SQlite:
    c.execute("INSERT INTO submissions (submitted_date, hash_sig, sig_name) VALUES (?, ?, ?)", (date, hash_sig, sig_name))

    # Save (commit) the changes
    conn.commit()

    # Close the connection
    conn.close()

def check_Record(sig_hash):
    t = (sig_hash,)

    conn = sqlite3.connect('vt_samples.db')

    # Obj to access the DB
    c = conn.cursor()

    # The first time the database is created the table 'submissions' will be empty:
    c.execute('SELECT COUNT(*) FROM submissions')
    (num_records,)=c.fetchone() # Always return a tuple

    if num_records > 0:
        c.execute('SELECT sig_name FROM submissions WHERE hash_sig=?', t)
        result = c.fetchone()
        return result
    else:
        return None # first time the Db is utilized

    # Close the connection
    conn.close()
