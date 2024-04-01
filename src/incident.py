from flask import Flask, request, jsonify, session
from pymongo import MongoClient
import datetime
from datetime import timedelta
from marshmallow import Schema, fields, ValidationError, validate
import config
import json
from bson import json_util
from bson.objectid import ObjectId
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user
from flask_user import current_user, login_required, roles_required, UserManager, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
import redis


app = Flask(__name__)

app.config['SECRET_KEY'] = config.APP_SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = config.DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['USER_ENABLE_EMAIL'] = False
app.config['USER_ENABLE_USERNAME'] = True
app.config['SESSION_TYPE'] = 'redis'
app.config["SESSION_PERMANENT"] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=10)
app.config['SESSION_REDIS'] = redis.Redis(
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    password=config.REDIS_PASSWORD,
    username=config.REDIS_USERNAME
)

Session(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='0')
    email = db.Column(db.String(255), nullable=False, unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default='')
    first_name = db.Column(db.String(100), nullable=False, server_default='')
    last_name = db.Column(db.String(100), nullable=False, server_default='')

    roles = db.relationship('Role', secondary='user_roles')

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

user_manager = UserManager(app, db, User)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    if not User.query.filter(User.email == 'admin@app.com').first():
        user = User(
            email='admin@app.com',
            email_confirmed_at=datetime.datetime.utcnow(),
            password=generate_password_hash(config.INITIAL_ADMIN_PASSWORD),
            active='1'
        )
        user.roles.append(Role(name='Admin'))
        db.session.add(user)
        db.session.commit()

# Connect to MongoDB
incident_client = MongoClient(
    config.MONGO_URI,
    username=config.MONGO_USERNAME,
    password=config.MONGO_PASSWORD,
    authSource=config.MONGO_AUTH_DB
)
incident_db = incident_client[config.MONGO_DB] 

# Incident Serializer class 
class IncidentSchema(Schema): 
    name = fields.Str(required=True)
    description = fields.Str(required=True)
    state = fields.Str(required=True, validate=validate.OneOf(["Resolved", "Maintenance", "Firing"])) 

@app.route('/register', methods=['POST'])
def register():
    email = request.json['email']
    password = request.json['password']
    first_name = request.json['first_name']
    last_name = request.json['last_name']

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(password)
    user = User(email=email, password=hashed_password, first_name=first_name, last_name=last_name)
    db.session.add(user)
    db.session.commit()

    member_role = Role.query.filter_by(name='Member').first()

    if member_role is None:
        member_role = Role(name='Member')
        db.session.add(member_role)

    user.roles.append(member_role)
    db.session.commit()

    return jsonify({'message': 'Registration successful'}), 201

@app.route('/login', methods=['POST'])
def login():
    if 'username' in session:
            response_dict = {'message': 'You have been logged in'}
            return jsonify(response_dict), 200
    
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter((User.email==email) & (User.active=='1')).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid email or password'}), 401

    login_user(user)
    session['logged_in'] = True
    session['username'] = user.email
    session['uuid'] = user.id

    return jsonify({'message': 'Login successful'}), 200

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/users/pending', methods=['GET'])
@roles_required('Admin')
def list_pending_users():
    pending_users = User.query.filter_by(active='0').all()
    return jsonify({'pending_users': [{'user_id': user.id, 'email': user.email} for user in pending_users]}), 200

@app.route('/users/activate', methods=['POST'])
@roles_required('Admin')
def activate_user():
    user_id = request.json['user_id']
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    user.active = True
    db.session.commit()

    return jsonify({'message': 'User activated successfully'}), 200

# Create Category API 
@app.route('/categories', methods=['POST']) 
@roles_required('Admin')
def create_category(): 
    category_name = request.json['name'] 
    try:
        incident_db.create_collection(category_name)
        return jsonify({'message': 'Category created successfully'}), 201 
    except:
        return jsonify({'message': 'Category creation failed'}), 400 

# List Category API 
@app.route('/categories', methods=['GET']) 
@login_required
def list_category(): 
    if not current_user.active:
        return jsonify({'message': 'Access denied. User is not active'}), 403
    
    try:
        filter = {"name": {"$regex": r"^(?!system\.)"}}
        categories = incident_db.list_collection_names(filter=filter)
        return jsonify(categories), 201 
    except:
        return jsonify({'message': 'Can not fetch categories'}), 400 

# Create Incident API 
@app.route('/categories/<category_name>/incidents', methods=['POST']) 
@roles_required('Admin')
def create_incident(category_name): 
    filter = {"name": category_name}
    category = incident_db.list_collection_names(filter=filter)
    if not category: 
        return jsonify({'message': 'Category does not exist'}), 404 
    
    try: 
        incident_data = IncidentSchema().load(request.json)
    except ValidationError as err: 
        return jsonify(err.messages), 400 

    incident_data['date'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
    incident_data['last_modified'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
    result = incident_db.category_name.insert_one(incident_data) 

    return jsonify({'message': 'Incident created successfully', 'id': str(result.inserted_id)}), 201

# Update Incident API 
@app.route('/categories/<category_name>/incidents/<incident_id>', methods=['PUT']) 
@roles_required('Admin')
def update_incident(category_name, incident_id): 
    filter = {"name": category_name}
    category = incident_db.list_collection_names(filter=filter)
    if not category:
        return jsonify({'message': 'Category does not exist'}), 404 
    
    try: 
        incident_data = IncidentSchema().load(request.json)
        incident_data['last_modified'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
    except ValidationError as err: 
        return jsonify(err.messages), 400 
    
    result = incident_db.category_name.update_one({'_id': ObjectId(incident_id)}, {'$set': incident_data}) 
    if result.modified_count == 1: 
        return jsonify({'message': 'Incident updated successfully'}), 200 
    else: 
        return jsonify({'message': 'Incident not found'}), 404 
    
# List Incidents API 
@app.route('/categories/<category_name>/incidents', methods=['GET']) 
@login_required
def list_incidents(category_name): 
    if not current_user.active:
        return jsonify({'message': 'Access denied. User is not active'}), 403

    filter = {"name": category_name}
    category = incident_db.list_collection_names(filter=filter)
    if not category:
        return jsonify({'message': 'Category does not exist'}), 404 
    
    incidents = list(incident_db.category_name.find({})) 

    return jsonify(json.loads(json_util.dumps(incidents))), 200 
