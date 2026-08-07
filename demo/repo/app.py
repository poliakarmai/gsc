"""Demo: уязвимое Flask-приложение для GSC демо."""
import sqlite3, pickle, os
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded-secret-key-1234567890abcdef'  # 🔴 GS029

DATABASE = 'demo.db'

def get_user(username: str):
    conn = sqlite3.connect(DATABASE)
    # 🔴 GS005: SQL injection через f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # 🔴 GS020: reflected XSS через f-string в HTML
    return f"<h1>Hello, {name}!</h1>"

@app.route('/eval')
def evaluate():
    expr = request.args.get('expr', '1+1')
    # 🔴 GS008: eval() с user input
    return str(eval(expr))

@app.route('/unpickle')
def unpickle_data():
    data = request.args.get('data', '')
    # 🔴 GS007: pickle.loads() с user input
    import base64
    return str(pickle.loads(base64.b64decode(data)))

if __name__ == '__main__':
    app.run(debug=True)
