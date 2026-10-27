import functools

from flask import abort, session


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)

    return wrapper
