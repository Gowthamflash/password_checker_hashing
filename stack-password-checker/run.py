"""Start Stack Password Checking and Hashing:  python run.py   ->  http://127.0.0.1:5000"""
from backend.app import create_app
from backend.config import Config

app = create_app()

if __name__ == "__main__":
    # Flask's built-in server is for development. For production see README (gunicorn / waitress).
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
