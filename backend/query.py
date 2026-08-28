import sqlite3
import json

conn = sqlite3.connect('data/intelligence.db')
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
for table in tables:
    t_name = table[0]
    cursor.execute(f"SELECT * FROM {t_name}")
    rows = cursor.fetchall()
    for row in rows:
        for val in row:
            if '1a04776511c6e31b' in str(val):
                print(f"FOUND IN TABLE {t_name}")
                print(row)
