from flask import Blueprint

agents_bp = Blueprint('agents', __name__, template_folder='templates')

from .routes import *