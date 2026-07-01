import sqlite3

conn = sqlite3.connect("app/data/feedback.db")
cursor = conn.cursor()

# Mostrar los últimos 20 feedbacks
cursor.execute("SELECT id, real_label, code FROM feedback ORDER BY id DESC LIMIT 20")
rows = cursor.fetchall()

for row in rows:
    print("\nID:", row[0])
    print("Label:", row[1])
    print("Code:\n", row[2])
    print("-" * 40)

conn.close()
