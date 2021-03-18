from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres:///loancenter'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

# Database models


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Product(db.Model):
    product_id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50))
    product_name = db.Column(db.String(50))
    description = db.Column(db.String(150))
    model = db.Column(db.String(50))
    price = db.Column(db.Integer)
    source = db.Column(db.String(50))
    state = db.Column(db.String(50))
    borrowed_by = db.Column(db.String(50))


class Log(db.Model):
    log_id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer)
    username = db.Column(db.String(50))
    state = db.Column(db.String(50))
    date = db.Column(db.DateTime)

# Support decorators


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# User routes


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data['name'] or not data['password']:
        return jsonify({'message': 'Bad Credentials'}), 401

    user = User.query.filter_by(name=data['name']).first()

    if not user:
        return jsonify({'message': 'Bad Credentials'}), 401

    if check_password_hash(user.password, data['password']):

        payload = {'id': user.id, 'name': user.name, 'admin': user.admin, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
        token = jwt.encode(payload, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return jsonify({'message': 'Bad Credentials'}), 401


@app.route('/user', methods=['GET'])
@login_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        user_data['password'] = user.password
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<user_id>', methods=['GET'])
@login_required
def get_one_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['name'] = user.name

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@login_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    try:
        new_user = User(name=data['name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
    except:
        return jsonify({'message': 'User with this username already exist'})
    return jsonify({'message': 'New user created'})


@app.route('/user/<user_id>', methods=['DELETE'])
@login_required
def delete_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted'})


@app.route('/user/<user_id>', methods=['PUT'])
@login_required
def promote_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()
    return jsonify({'message': 'User promoted to super user!'})


# Product routes


@app.route('/product', methods=['POST'])
@login_required
def create_product(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    data = request.get_json()

    new_product = Product(
        product_name=data['product_name'],
        description=data['description'],
        category=data['category'],
        model=data['model'],
        price=data['price'],
        source=data['source'],
        state='OK',
        borrowed_by=None
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'New product created'})


@app.route('/product', methods=['GET'])
@login_required
def get_all_products(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    products = Product.query.all()

    output = []

    # TODO Category
    for product in products:
        product_data = {}
        product_data['product_id'] = product.product_id
        product_data['category'] = product.category
        product_data['product_name'] = product.product_name
        product_data['description'] = product.description
        product_data['model'] = product.model
        product_data['price'] = product.price
        product_data['source'] = product.source
        product_data['state'] = product.state
        product_data['borrowed_by'] = product.borrowed_by
        output.append(product_data)

    return jsonify({'Products': output})


@app.route('/product/<product_id>', methods=['GET'])
@login_required
def get_one_product(current_user, product_id):
    product = Product.query.filter_by(product_id=product_id).first()

    if not product:
        return jsonify({'message': "product with that id doesn't exist"})

    output = []

    product_data = {}
    product_data['product_id'] = product.product_id
    product_data['category'] = product.category
    product_data['product_name'] = product.product_name
    product_data['description'] = product.description
    product_data['model'] = product.model
    product_data['price'] = product.price
    product_data['source'] = product.source
    product_data['state'] = product.state
    product_data['borrowed_by'] = product.borrowed_by
    output.append(product_data)

    return jsonify({'product': output})


@app.route('/product/<product_id>', methods=['PUT'])
@login_required
def change_product_state(current_user, product_id):
    new_state = request.get_json()
    current_username = current_user.name
    product = Product.query.filter_by(product_id=product_id).first()

    if not product:
        return jsonify({'message': "product with that id doesn't exist"})

    if new_state['state'] == "Ok" or new_state['state'] == "Borrowed" or new_state['state'] == "Broken":
        _add_log(product_id, new_state['state'], current_username)
        product.state = new_state['state']

        if product.state == "Ok":
            product.borrowed_by = None

        db.session.commit()
        return jsonify({'message': "Product state changed"})

    return jsonify({'message': "product can't get this state"})


def _add_log(product_id, state, current_username):
    # TODO change to decorator
    new_log = Log(
        product_id=product_id,
        username=current_username,
        state=state,
        date=datetime.datetime.now(),
    )
    db.session.add(new_log)
    db.session.commit()


@app.route('/product/<product_id>', methods=['DELETE'])
@login_required
def delete_product(current_user, product_id):
    if not current_user.admin:
        return jsonify({'message': 'Only admin have access to this resource'})

    product_to_delete = Product.query.filter_by(product_id=product_id).first()

    if not product_to_delete:
        return jsonify({'message': 'No such product'})

    db.session.delete(product_to_delete)
    db.session.commit()

    return jsonify({'message': 'Product successfully deleted'})


# Log routes


@app.route('/logs', methods=['GET'])
@login_required
def get_all_logs(current_user):
    logs = Log.query.all()
    output = []

    for log in logs:
        log_data = {}
        log_data['log_id'] = log.log_id
        log_data['product_id'] = log.product_id
        log_data['username'] = log.username
        log_data['state'] = log.state
        log_data['date'] = log.date
        output.append(log_data)

    return jsonify({'logs': output})


@app.route('/logs/<product_id>', methods=['GET'])
@login_required
def get_product_logs(current_user, product_id):
    logs = Log.query.filter_by(product_id=product_id)

    output = []

    for log in logs:
        log_data = {}
        log_data['log_id'] = log.log_id
        log_data['product_id'] = log.product_id
        log_data['username'] = log.username
        log_data['state'] = log.state
        log_data['date'] = log.date
        output.append(log_data)

    return jsonify({'logs': output})


@app.route('/search', methods=['GET'])
@login_required
def search(current_user):
    product_name = request.args.get('product_name')

    if not product_name:
        return jsonify({'Search result': []})

    products = Product.query.filter(Product.product_name.startswith(product_name)).all()

    output = []

    for product in products:
        product_data = {}
        product_data['product_name'] = product.product_name
        product_data['category'] = product.category
        output.append(product_data)

    return jsonify({'Search result': output})


if __name__ == '__main__':
    app.run(debug=True)

# TODO separate into other files
