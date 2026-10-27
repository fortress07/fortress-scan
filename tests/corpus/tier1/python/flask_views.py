import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    name = request.args.get("name")
    return str(conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall())  # fsb-expect: FSB-SQL-001


@app.route("/user-safe")
def user_safe():
    conn = sqlite3.connect("app.db")
    return str(conn.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),)).fetchall())


@app.route("/archive")
def archive():
    target = request.args.get("dir", "")
    os.system("tar czf /tmp/out.tgz " + target)  # fsb-expect: FSB-CMD-001
    subprocess.run(["tar", "czf", "/tmp/out.tgz", target], check=False)
    return "ok"


@app.route("/session", methods=["POST"])
def session_restore():
    return str(pickle.loads(request.get_data()))  # fsb-expect: FSB-DESER-001


@app.route("/settings", methods=["POST"])
def settings():
    data = yaml.safe_load(request.get_data())
    return str(data)


@app.route("/next")
def next_page():
    return redirect(request.args.get("url"))  # fsb-expect: FSB-REDIR-001
