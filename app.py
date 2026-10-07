import time
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect

from config import Config
from database.db import db, init_db
from database.models import User, UserKey, History
from encryption.key_manager import ALGORITHMS, create_key, key_for_encrypt, key_for_decrypt
from auth import all_blueprints
from utils.security import add_security_headers
from utils.validators import validate_key_name


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    init_db(app)
    CSRFProtect(app)
    add_security_headers(app)

    lm = LoginManager(app)
    lm.login_view = "login.login"
    lm.user_loader(lambda uid: db.session.get(User, int(uid)))
    for bp in all_blueprints:
        app.register_blueprint(bp)

    def own_key(key_id, algorithm):
        k = UserKey.query.filter_by(id=key_id, user_id=current_user.id).first()
        if not k or k.algorithm != algorithm:
            return None
        return k

    def log(op, algo, key, n, ct, ms):
        db.session.add(History(user_id=current_user.id, operation=op, algorithm=algo,
                               key_name=key.name, input_chars=n, ciphertext=ct, elapsed_ms=ms))
        db.session.commit()

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user.is_authenticated else "login.login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        recent = History.query.filter_by(user_id=current_user.id).order_by(History.id.desc()).limit(5).all()
        return render_template("dashboard.html", recent=recent,
                               key_count=UserKey.query.filter_by(user_id=current_user.id).count())

    def crypto_view(mode):
        keys = UserKey.query.filter_by(user_id=current_user.id).order_by(UserKey.name).all()
        result, form = None, {"algorithm": "AES", "key_id": "", "text": ""}
        if request.method == "POST":
            form = {k: request.form.get(k, "") for k in ("algorithm", "key_id", "text")}
            text, algo = form["text"].strip(), form["algorithm"]
            key = own_key(form["key_id"], algo) if algo in ALGORITHMS else None
            if not text:
                flash("Enter some text first.", "error")
            elif len(text) > app.config["MAX_TEXT_LENGTH"]:
                flash(f"Text is limited to {app.config['MAX_TEXT_LENGTH']:,} characters.", "error")
            elif not key:
                flash("Choose a key that matches the selected algorithm.", "error")
            else:
                try:
                    start = time.perf_counter()
                    mod = ALGORITHMS[algo]
                    if mode == "encrypt":
                        result = mod.encrypt(text, key_for_encrypt(key))
                    else:
                        result = mod.decrypt("".join(text.split()), key_for_decrypt(key))
                    ms = (time.perf_counter() - start) * 1000
                    log(mode, algo, key, len(text), result if mode == "encrypt" else None, ms)
                except Exception:
                    flash("Decryption failed. Check the key and make sure the ciphertext is unchanged.", "error")
        return render_template(f"{mode}.html", keys=keys, result=result, form=form)

    @app.route("/encrypt", methods=["GET", "POST"])
    @login_required
    def encrypt_page():
        return crypto_view("encrypt")

    @app.route("/decrypt", methods=["GET", "POST"])
    @login_required
    def decrypt_page():
        return crypto_view("decrypt")

    @app.route("/keys", methods=["GET", "POST"])
    @login_required
    def keys_page():
        if request.method == "POST":
            name, algo = request.form.get("name", "").strip(), request.form.get("algorithm", "")
            if not validate_key_name(name) or algo not in ALGORITHMS:
                flash("Give the key a name (up to 60 characters) and pick an algorithm.", "error")
            else:
                create_key(current_user.id, name, algo)
                flash(f"{algo} key \"{name}\" created.", "ok")
            return redirect(url_for("keys_page"))
        keys = UserKey.query.filter_by(user_id=current_user.id).order_by(UserKey.id.desc()).all()
        return render_template("keys.html", keys=keys)

    @app.route("/keys/<int:key_id>/delete", methods=["POST"])
    @login_required
    def delete_key(key_id):
        k = UserKey.query.filter_by(id=key_id, user_id=current_user.id).first() or abort(404)
        db.session.delete(k)
        db.session.commit()
        flash(f"Key \"{k.name}\" deleted. Data encrypted with it can no longer be decrypted.", "ok")
        return redirect(url_for("keys_page"))

    @app.route("/history")
    @login_required
    def history_page():
        rows = History.query.filter_by(user_id=current_user.id).order_by(History.id.desc()).limit(200).all()
        return render_template("history.html", rows=rows)

    @app.route("/history/clear", methods=["POST"])
    @login_required
    def clear_history():
        History.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash("History cleared.", "ok")
        return redirect(url_for("history_page"))

    @app.route("/comparison", methods=["GET", "POST"])
    @login_required
    def comparison_page():
        from utils.benchmark import run_benchmark
        size = 1000
        if request.method == "POST":
            try:
                size = max(10, min(int(request.form.get("size", 1000)), 5000))
            except ValueError:
                pass
        return render_template("comparison.html", rows=run_benchmark(size), size=size)

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
