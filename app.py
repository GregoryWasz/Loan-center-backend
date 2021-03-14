from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres:///loancenter'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


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

        return f(current_user, *args, *kwargs)

    return decorated


@login_required
@app.route('/user', methods=['GET'])
def get_all_users(current_user):
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


@app.route('/user/<id>', methods=['GET'])
def get_one_user(id):

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['name'] = user.name

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    try:
        new_user = User(name=data['name'], password=hashed_password, admin=False)
        db.session.add(new_user)
        db.session.commit()
    except:
        return jsonify({'message': 'User with this username already exist'})
    return jsonify({'message': 'New user created'})


@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):

    user = User.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted'})


@app.route('/login', methods=['POST'])
def rest_login():
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


if __name__ == '__main__':
    app.run(debug=True)