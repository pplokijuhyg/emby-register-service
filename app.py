import os
import re
import secrets
import sqlite3
import string
import hmac
import hashlib
import urllib3
from datetime import datetime, timedelta
from functools import wraps
import requests
from flask import (Flask, flash, redirect, render_template, request, session,
                   url_for, Response)
from flask_paginate import Pagination, get_page_args
from authlib.integrations.flask_client import OAuth
import csv
import io

from emby_register_service import create_app, database

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        database.init_db()
    app.run(host='0.0.0.0', port=5000)