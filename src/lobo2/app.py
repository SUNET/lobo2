from flask import Flask
import os

app = Flask(__name__)
app.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
app.secret_key = os.urandom(24)
