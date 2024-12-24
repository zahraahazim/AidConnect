# helpers.py
import requests

def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


def apology(message, code=400):
    """Render message as an apology to user."""
    return render_template("apology.html", top=code, bottom=message), code

def login_required(f):
    """Decorator to require login for access."""
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrap
