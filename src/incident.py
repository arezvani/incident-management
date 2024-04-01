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
from flask_restx import Resource, Api, fields as f
import redis


app = Flask(__name__)
api = Api(app, version='1.0', title='Incident Management API', description='API for managing incidents and categories')

user_model = api.model('Users', {
    'email': f.String(required=True, description='User email'),
    'password': f.String(required=True, description='User password'),
    'first_name': f.String(required=True, description='User first_name'),
    'last_name': f.String(required=True, description='User last_name')
})

login_model = api.model('Login', {
    'email': f.String(required=True, description='User email'),
    'password': f.String(required=True, description='User password')
})

userid_model = api.model('UserID', {
    'user_id': f.String(required=True, description='User id')
})

category_model = api.model('Category', {
    'name': f.String(required=True, description='Category name')
}) 

incident_model = api.model('Incident', {
    'name': f.String(required=True, description='Incident name'),
    'description': f.String(required=True, description='Incident description'),
    'state': f.String(
        required=True,
        description='Incident state',
        enum=["Resolved", "Maintenance", "Firing"],
        enum_error_message='Invalid state value. Allowed values are: Resolved, Maintenance, Firing'
    )
})

delete_incident_model = api.model('Delete Incident', {
    'id': f.String(required=True, description='Incident id')
})

user_ns = api.namespace('users', description='users operations') 
category_ns = api.namespace('categories', description='Category operations') 
incident_ns = api.namespace('incidents', description='Incident operations')

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

@user_ns.route('/register', methods=['POST'])
class Register(Resource):
    @api.doc(responses={201: 'User created', 400: 'User creation failed'}) 
    @api.expect(user_model)
    def post(self):
        email = request.json['email']
        password = request.json['password']
        first_name = request.json['first_name']
        last_name = request.json['last_name']

        if User.query.filter_by(email=email).first():
            return {'message': 'Email already registered'}, 400

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

        return {'message': 'Registration successful'}, 201

@user_ns.route('/login', methods=['POST'])
class Login(Resource):
    @api.doc(responses={200: 'User login successfully', 401: 'Invalid email or password'}) 
    @api.expect(login_model)    
    def post(self):
        if 'username' in session:
            response_dict = {'message': 'You have been logged in'}
            return response_dict, 200
        
        email = request.json['email']
        password = request.json['password']

        user = User.query.filter((User.email==email) & (User.active=='1')).first()

        if not user or not check_password_hash(user.password, password):
            return {'message': 'Invalid email or password'}, 401

        login_user(user)
        session['logged_in'] = True
        session['username'] = user.email
        session['uuid'] = user.id

        return {'message': 'Login successful'}, 200

@user_ns.route('/logout', methods=['POST'])
class Logout(Resource):
    @login_required
    def post(self):
        logout_user()
        session.pop('username', None)
        return {'message': 'Logout successful'}, 200

@user_ns.route('/pending', methods=['GET'])
class PendingUsers(Resource):
    @roles_required('Admin')
    @api.doc(responses={200: 'List pending users successfully', 403: 'Permission denied'}) 
    def get(self):
        pending_users = User.query.filter_by(active='0').all()
        return {'pending_users': [{'user_id': user.id, 'email': user.email} for user in pending_users]}, 200

@user_ns.route('/activate', methods=['POST'])
class ActivateUsers(Resource):
    @roles_required('Admin')
    @api.doc(responses={200: 'User activated successfully', 404: 'User not found'}) 
    @api.expect(userid_model)  
    def post(self):
        user_id = request.json['user_id']
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        user.active = True
        db.session.commit()

        return {'message': 'User activated successfully'}, 200

# Category API 
@category_ns.route('/', methods=['GET', 'POST', 'DELETE']) 
class Category(Resource):
    @roles_required('Admin')
    @api.doc(responses={201: 'Category created', 400: 'Category creation failed'}) 
    @api.expect(category_model)
    def post(self):
        category_name = request.json['name'] 
        try:
            incident_db.create_collection(category_name)
            return {'message': 'Category created successfully'}, 201 
        except:
            return {'message': 'Category creation failed'}, 400 

    @login_required
    @api.doc(responses={200: 'Categories listed', 400: 'Failed to fetch categories'})
    def get(self):
        try:
            filter = {"name": {"$regex": r"^(?!system\.)"}}
            categories = incident_db.list_collection_names(filter=filter)
            return categories, 200
        except:
            return {'message': 'Can not fetch categories'}, 400 

    @roles_required('Admin')
    @api.doc(responses={201: 'Category deleted', 400: 'Category deletion failed'}) 
    @api.expect([category_model])
    def delete(self):
        try:
            categories = request.json
            for category in categories:
                category_name = category['name']
                filter = {'name': category_name}
                existing_category = incident_db.list_collection_names(filter=filter)

                if existing_category:
                    incident_db.drop_collection(category_name)
                else:
                    return {'message': f'Category {category_name} does not exist'}, 400 

            return {'message': 'Categories deleted successfully'}, 201
        except:
            return {'message': 'Can not delete categories'}, 400 

# Incident API 
@incident_ns.route('/<category_name>', methods=['GET', 'POST', 'DELETE']) 
class Incident(Resource): 
    @roles_required('Admin')
    @api.doc(responses={201: 'Incident created', 400: 'Incident creation failed', 404: 'Category not found'}) 
    @api.expect(incident_model)
    def post(self, category_name):
        filter = {"name": category_name}
        category = incident_db.list_collection_names(filter=filter)
        if not category: 
            return {'message': 'Category does not exist'}, 404 
        
        try: 
            incident_data = IncidentSchema().load(request.json)
        except ValidationError as err: 
            return err.messages, 400 

        incident_data['date'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
        incident_data['last_modified'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
        result = incident_db.category_name.insert_one(incident_data) 

        return {'message': 'Incident created successfully', 'id': str(result.inserted_id)}, 201

    @login_required
    @api.doc(responses={200: 'Incidents listed', 400: 'Failed to fetch incidents', 404: 'Category not found'})
    def get(self, category_name):
        try:
            filter = {"name": category_name}
            category = incident_db.list_collection_names(filter=filter)
            if not category:
                return {'message': 'Category does not exist'}, 404 
            
            incidents = list(incident_db.category_name.find({})) 

            return json.loads(json_util.dumps(incidents)), 200 
        
        except:
            return {'message': 'Failed to fetch incidents'}, 400 

    @roles_required('Admin')
    @api.doc(responses={201: 'Incidents deleted', 400: 'Failed to delete incidents', 404: 'Incident not found'})
    @api.expect([delete_incident_model])
    def delete(self, category_name):
        deleted_count = []
        incidents = request.json

        filter = {"name": category_name}
        category = incident_db.list_collection_names(filter=filter)

        if not category:
            return {'message': 'Category does not exist'}, 404 

        for incident in incidents:
            incident_id = incident['id']
            result = incident_db.category_name.delete_one({'_id': ObjectId(incident_id)})
            deleted_count.append(int(result.deleted_count))

        if all(deleted_count): 
            return {'message': 'Incident deleted successfully'}, 201
        else: 
            return {'message': 'Incident not found'}, 404

# Update Incident API 
@incident_ns.route('/<category_name>/<incident_id>', methods=['PUT', 'DELETE'])
class UpdateIncident(Resource):
    @roles_required('Admin')
    @api.doc(responses={201: 'Incident updated', 400: 'Failed to update incident', 404: 'Incident not found'}) 
    @api.expect(incident_model)
    def put(self, category_name, incident_id):
        filter = {"name": category_name}
        category = incident_db.list_collection_names(filter=filter)
        if not category:
            return {'message': 'Category does not exist'}, 404 
        
        try: 
            incident_data = IncidentSchema().load(request.json)
            incident_data['last_modified'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") 
        except ValidationError as err: 
            return err.messages, 400 
        
        result = incident_db.category_name.update_one({'_id': ObjectId(incident_id)}, {'$set': incident_data}) 
        if result.modified_count == 1: 
            return {'message': 'Incident updated successfully'}, 201
        else: 
            return {'message': 'Incident not found'}, 404 
    
    @roles_required('Admin')
    @api.doc(responses={201: 'Incident deleted', 400: 'Failed to delete incident', 404: 'Incident not found'}) 
    def delete(self, category_name, incident_id):
        filter = {"name": category_name}
        category = incident_db.list_collection_names(filter=filter)
        if not category:
            return {'message': 'Category does not exist'}, 404 
        
        result = incident_db.category_name.delete_one({'_id': ObjectId(incident_id)}) 
        if result.deleted_count == 1: 
            return {'message': 'Incident deleted successfully'}, 201
        else: 
            return {'message': 'Incident not found'}, 404
