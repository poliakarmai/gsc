"""
SQLi test corpus for GS005 — Python patterns.
Every line should be detected (unless marked SAFE).
"""
import something

# ═══ POSITIVE — String Interpolation ════════════════════════════════════
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
cursor.execute("SELECT * FROM users WHERE name = '%s'" % request.args.get('name'))
cursor.execute("SELECT * FROM products WHERE category = '{}'".format(category))
cursor.execute("SELECT * FROM orders WHERE id = " + order_id)
cursor.executemany(f"INSERT INTO log VALUES ({data})")

# ═══ POSITIVE — UNION-based ═════════════════════════════════════════════
cursor.execute(f"SELECT name FROM users WHERE id = {uid} UNION SELECT password FROM admins")
cursor.execute("SELECT * FROM products WHERE cat = '" + cat + "' UNION SELECT * FROM secrets")

# ═══ POSITIVE — Boolean-based Blind ═════════════════════════════════════
cursor.execute(f"SELECT * FROM users WHERE name = '{username}' OR '1'='1'")
cursor.execute(f"SELECT * FROM items WHERE id = {item_id} OR 1=1--")

# ═══ POSITIVE — Time-based Blind ════════════════════════════════════════
cursor.execute(f"SELECT * FROM users WHERE id = {uid}; SELECT SLEEP(5)")
cursor.execute("SELECT * FROM data WHERE key = '" + key + "'; SELECT pg_sleep(10)")
cursor.execute("SELECT * FROM dbo.users WHERE name = '" + name + "'; WAITFOR DELAY '00:00:05'")

# ═══ POSITIVE — Stacked Queries ═════════════════════════════════════════
cursor.execute(f"SELECT * FROM users WHERE id = {uid}; DROP TABLE logs; SELECT * FROM secrets")

# ═══ POSITIVE — Django ORM ═════════════════════════════════════════════
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.raw("SELECT * FROM users WHERE id = %s" % uid)
User.objects.extra(where=f"name = '{name}' AND active = 1")
User.objects.annotate(full_name=RawSQL(f"first_name || ' ' || last_name"))

# ═══ POSITIVE — SQLAlchemy ═════════════════════════════════════════════
session.execute(text(f"SELECT * FROM users WHERE id = {uid}"))
session.execute(text("SELECT * FROM users WHERE email = '%s'" % email))
engine.execute(text(f"DELETE FROM sessions WHERE token = '{token}'"))

# ═══ POSITIVE — Second-order ═══════════════════════════════════════════
row = cursor.fetchone()
cursor.execute(f"SELECT * FROM audit WHERE user = '{row['username']}'")

# ═══ POSITIVE — Pandas ═════════════════════════════════════════════════
pd.read_sql(f"SELECT * FROM sales WHERE region = '{region}'", conn)

# ═══ POSITIVE — DynamoDB (NoSQL in Python) ═════════════════════════════
table.scan(FilterExpression=f"username = '{user}'")
table.query(KeyConditionExpression=f"pk = '{partition_key}'")

# ═════════════════════════════════════════════════════════════════════════
# SAFE PATTERNS — should NOT fire
# ═════════════════════════════════════════════════════════════════════════
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
session.query(User).filter(User.name == name)
User.objects.filter(name=name)
cursor.execute("PRAGMA table_info(users)")
bot.reply_text(f"Hello {user}")
text("This is just a message about SQL injection")
