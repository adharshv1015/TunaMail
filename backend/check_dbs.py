import sqlite3
import glob
for db_file in glob.glob(r'C:\Users\Asus\Documents\MAKTAL\backend\data\*.db'):
    try:
        c = sqlite3.connect(db_file)
        result = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'").fetchall()
        c.close()
        print(f'{db_file}: feedback table exists? {bool(result)}')
    except Exception as e:
        print(f'Error on {db_file}: {e}')
