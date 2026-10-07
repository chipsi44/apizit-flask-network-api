"""Normal Flask application; APIZIT owns the managed runtime adapter."""

from flask import Flask

app = Flask(__name__, static_folder=None)
app.config.update(MAX_CONTENT_LENGTH=65536, PROPAGATE_EXCEPTIONS=False)

from app import routes  # noqa: E402, F401
