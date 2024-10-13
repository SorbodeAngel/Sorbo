import os
import glob
import shutil
import requests
import base64
import sqlite3


from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from helpers import apology, login_required, lookup, usd
from datetime import datetime, timedelta

# Configure application
app = Flask(__name__, static_url_path='/project/static')

UPLOAD_FOLDER = '/workspaces/147406916/project/static/pictures/'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.secret_key = 'ABC'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")

db.execute("""CREATE TABLE IF NOT EXISTS shop_items (
           item_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
   product_name TEXT NOT NULL,
   origin TEXT NOT NULL,
   price INTEGER NOT NULL,
   data BLOB NOT NULL,
   extra_info TEXT
   )
           """)

db.execute("""CREATE TABLE IF NOT EXISTS shop_record (
           sales_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
   item_id INTEGER NOT NULL,
   user_id INTEGER NOT NULL,
   product_name TEXT NOT NULL,
   quantity INTEGER NOT NULL,
   price INTEGER NOT NULL,
   date TEXT,
   extra_info TEXT,
   FOREIGN KEY(user_id) REFERENCES users(user_id)
   )
           """)

db.execute("""CREATE TABLE IF NOT EXISTS shop_cart (
            user_id INTEGER NOT NULL,
   item_id INTEGER NOT NULL,
   product_name TEXT,
   quantity INTEGER NOT NULL,
   price INTEGER NOT NULL,
   date TEXT,
   FOREIGN KEY(user_id) REFERENCES users(user_id)
   )
           """)

db.execute("""CREATE TABLE IF NOT EXISTS users (
           user_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
   first_name TEXT NOT NULL,
   last_name TEXT NOT NULL,
   email TEXT NOT NULL,
   username TEXT NOT NULL,
   hash TEXT NOT NULL,
   place_id TEXT NOT NULL,
   extra_info TEXT,
   FOREIGN KEY(user_id) REFERENCES users(user_id)
   )
           """)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.context_processor
def inject_user_id():
    user_id = session.get("user_id")
    return dict(user_id=user_id)


@app.route('/', methods=["GET", "POST"])
def index():
    return render_template("index.html")


@app.route('/cafe', methods=["GET", "POST"])
def cafe():
    return render_template("cafe.html")


@app.route('/cafetero', methods=["GET", "POST"])
def cafetero():
    return render_template("cafetero.html")


@app.route('/sobre_mi', methods=["GET", "POST"])
def sobre_mi():
    return render_template("sobre_mi.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    pers_data = db.execute("SELECT * FROM users WHERE user_id = ?", session["user_id"])

    order_list = db.execute("SELECT * FROM shop_record")

    buyers = []
    for order in order_list:
        if order['user_id'] not in buyers:
            buyers.append(int(order['user_id']))

    buyers_info = []
    for buyer in buyers:
        info = db.execute("SELECT * FROM users WHERE user_id = ?", buyer)
        buyers_info.extend(info)

    inventory = db.execute("SELECT item_id, product_name, origin, price, data, extra_info FROM shop_items")

    items = [{
        'item_id': item['item_id'],
        'name': item['product_name'],
        'origin': item['origin'],
        'price': item['price'],
        'data': base64.b64encode(item['data']).decode('utf-8'),
        'extra_info': item['extra_info'],
    } for item in inventory]

    return render_template("profile.html", pers_data=pers_data[0], order_list=order_list, items=items, buyers=buyers, buyers_info=buyers_info)


@app.route("/update_profile", methods=["GET", "POST"])
@login_required
def update_profile():
    try:
        pers_data = db.execute("SELECT * FROM users WHERE user_id = ?", session["user_id"])

        if not request.form.get("username") or not request.form.get("password") or not request.form.get("confirmation"):
            username = pers_data[0]['username']
            password = pers_data[0]['hash']
        else:
            username = request.form.get("username")
            password = generate_password_hash(request.form.get("password"))

            if request.form.get("password") != request.form.get("confirmation"):
                return apology("invalid username and/or password", 403)

        if not request.form.get("first_name") or not request.form.get("last_name") or not request.form.get("email"):
            first_name = pers_data[0]['first_name']
            last_name = pers_data[0]['last_name']
            email = pers_data[0]['email']
        else:
            first_name = request.form.get("first_name")
            last_name = request.form.get("last_name")
            email = request.form.get("email")

        if not request.form.get("street") or not request.form.get("street_no") or not request.form.get("postal_code") or not request.form.get("city") or not request.form.get("country"):
            place_id = pers_data[0]['place_id']
        else:
            street = request.form.get("street")
            street_no = request.form.get("street_no")
            postal_code = request.form.get("postal_code")
            city = request.form.get("city")
            country = request.form.get("country")

            place_id = street + " " + street_no + ", " + postal_code + ", " + city + ", " + country

        db.execute("UPDATE users SET username = ?, hash = ?, first_name = ?, last_name = ?, email = ?, place_id = ? WHERE user_id = ?",
                   username, password, first_name, last_name, email, place_id, session["user_id"])

        return redirect("/profile")

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return "An error occurred while interacting with the database.", 500

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "An unexpected error occurred.", 500


@app.route('/remove_item', methods=['GET'])
def remove_item():
    try:
        item_id = request.args.get('item_id')

        db.execute("DELETE FROM shop_items WHERE item_id = ?", item_id)

        return redirect('/profile')

    except (TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/upload', methods=['POST'])
def upload_item():
    if 'picture' not in request.files:
        return 'No file part'

    file = request.files['picture']

    if file.filename == '':
        return 'No selected file'

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

    with open(filepath, 'rb') as file:
        blob_data = file.read()

    name = request.form.get("name")
    origin = request.form.get("origin")
    price = request.form.get("price")
    extra_info = request.form.get("extra_info")

    db.execute("INSERT INTO shop_items (product_name, origin, price, data, extra_info) VALUES (?, ?, ?, ?, ?)",
               name, origin, price, blob_data, extra_info)

    return redirect('/profile')


@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        check = db.execute("SELECT * FROM users WHERE username = ?", username)

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return "must provide username"

        # Query database for if username is taken
        elif check:
            return "username already taken"

        # Ensure password was submitted
        elif not password or not confirmation:
            return "must provide passwords"

        # Check if passwords match
        elif password != confirmation:
            return "passwords must match"

        # Add location
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")

        street = request.form.get("street")
        street_no = request.form.get("street_no")
        postal_code = request.form.get("postal_code")
        city = request.form.get("city")
        country = request.form.get("country")

        address = street + " " + street_no + ", " + postal_code + ", " + city  + ", " + country

        # fill in the geocode API

        db.execute("INSERT INTO users(username, first_name, last_name, email, hash, place_id) VALUES (?, ?, ?, ?, ?, ?)",
                           username, first_name, last_name, email, generate_password_hash(password), address)

        # Ensure username exists and password is correct
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return "something went wrong, please try again"

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    elif request.method == "GET":
        return render_template("register.html")


# Database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/shop", methods=["GET", "POST"])
def shop():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        if request.method == "POST":
            if request.is_json:
                data = request.get_json()
                item_id = data.get('id')

                now = datetime.now()
                date = now.strftime("%Y-%m-%d")

                if not session.get("user_id"):
                    return redirect("login.html")

                cursor.execute("INSERT INTO shop_cart (user_id, item_id, product_name, price, quantity, date) VALUES (?, ?, ?, ?, ?, ?)",
                               (session["user_id"], item_id, 'Cafe de Origen', 42000, 1, date))

                conn.commit()

                return jsonify({'status': 'Item added to cart'})

        elif request.method == "GET":
            cursor.execute("SELECT COUNT(*) FROM shop_items WHERE product_name = 'Cafe de Origen'")
            if cursor.fetchone()[0] == 0:
                file_path = '/workspaces/147406916/project/static/pictures/bolsa_cafe.jpg'

                try:
                    with open(file_path, 'rb') as f:
                        blob_data = f.read()
                except FileNotFoundError:
                    return "The image file was not found.", 404

                cursor.execute("INSERT INTO shop_items (product_name, origin, price, data, extra_info) VALUES (?, ?, ?, ?, ?)",
                               ("Cafe de Origen", "Nariño", 42000, blob_data, "Muy Rico"))
                conn.commit()

            cursor.execute("SELECT item_id, product_name, origin, price, data, extra_info FROM shop_items")

            inventory = cursor.fetchall()

            items = [{
                'item_id': item['item_id'],
                'name': item['product_name'],
                'origin': item['origin'],
                'price': item['price'],
                'data': base64.b64encode(item['data']).decode('utf-8'),
                'extra_info': item['extra_info'],
            } for item in inventory]

            return render_template('shop.html', items=items)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return "An error occurred while interacting with the database.", 500

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "An unexpected error occurred.", 500

    finally:
        cursor.close()
        conn.close()


@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    # recall what is already put in the cart
    cart = db.execute("SELECT item_id, quantity FROM shop_cart WHERE user_id = ?", session["user_id"])

    cart_list = []
    if cart:
        for item in cart:
            info = db.execute("SELECT product_name, price, data FROM shop_items WHERE item_id = ?", int(item['item_id']))
            cart_item = {
                'name': info[0]['product_name'],
                'id': int(item['item_id']),
                'data': base64.b64encode(info[0]['data']).decode('utf-8'),
                'quantity': item['quantity'],
                'price': int(info[0]['price']) * int(item['quantity']),
                'total_price': int(item['quantity']) * int(info[0]['price'])
            }
            cart_list.append(cart_item)

    # calculate the total price of all the products
    total_topay = sum(item['total_price'] for item in cart_list)

    return render_template('cart.html', cart_list=cart_list, total_topay=total_topay)


@app.route("/add_cart", methods=["GET", "POST"])
@login_required
def add_cart():
    try:
        item_id = request.args.get('item_id')
        quantity = request.args.get('quantity')

        # Get the current date and time
        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")

        in_cart = db.execute("SELECT quantity, price FROM shop_cart WHERE item_id = ? AND user_id = ?", int(item_id), session["user_id"])

        if in_cart:
            quantity = int(in_cart[0]["quantity"]) + int(quantity)

            db.execute("UPDATE shop_cart SET quantity = ? WHERE user_id = ? AND item_id = ?", quantity, session['user_id'], item_id)

        else:
            item = db.execute("SELECT price FROM shop_items WHERE item_id = ?", int(item_id))

            db.execute("INSERT INTO shop_cart(user_id, item_id, quantity, price, date) VALUES (?, ?, ?, ?, ?)",
                session["user_id"], int(item_id), int(quantity), int(quantity) * int(item[0]['price']), date)

        return redirect('/cart')

    except (TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route("/add_order", methods=["GET", "POST"])
@login_required
def add_order():
    now = datetime.now()
    date = now.strftime("%Y-%m-%d")

    quantity = request.args.get('quantity')

    try:
        in_cart = db.execute("SELECT * FROM shop_cart WHERE user_id = ?", session["user_id"])

        if in_cart:
            for item in in_cart:
                info = db.execute("SELECT * FROM shop_items WHERE item_id = ?", item['item_id'])

                price = info[0]['price'] * int(quantity)

                db.execute("INSERT INTO shop_record(item_id, user_id, product_name, quantity, price, date) VALUES (?, ?, ?, ?, ?, ?)",
                        item['item_id'], session["user_id"], info[0]['product_name'], quantity, price, date)

        db.execute("DELETE FROM shop_cart WHERE user_id = ?", session['user_id'])

    except (TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500

    return render_template('success.html')


@app.route("/resolve_order", methods=["GET", "POST"])
@login_required
def resolve_order():
    try:
        sales_id = request.args.get('sales_id')

        db.execute("DELETE FROM shop_record WHERE sales_id = ?", sales_id)

        return redirect('/profile')

    except (TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred"}), 500


if __name__ == '__main__':
    app.run(debug=True)
