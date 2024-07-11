from flask import Flask, request, flash, jsonify, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity)
from datetime import datetime, timedelta


app = Flask(__name__)

app.config['SECRET_KEY'] = "Vj?Irxdfxbfxfbxbb"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres.vgqyfisllqzphursduin:yunusaumar1@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
db = SQLAlchemy()
db.init_app(app)
jwt = JWTManager(app)



class USERS(db.Model):
    userId = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String, nullable=False)
    lastName = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    phone = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)

    def __repr__(self):
        return jsonify({
            "userId": self.userId, 
            "firstName": self.firstName, 
            "lastName": self.lastName, 
            "email": self.email, 
            "password":self.password
            })
    def __init__(self, firstName, lastName, email, phone, password):
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.phone = phone
        self.password = password



class ORGANISATION(db.Model):
    orgId = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    description = db.Column(db.String, nullable=False)
    userId = db.Column(db.Integer, db.ForeignKey('users.userId'), nullable=False)

    def __repr__(self):
        return jsonify({
            "orgId": self.orgId, 
            "name": self.name, 
            "description": self.description,
            "userId": self.userId
            })
    def __init__(self, name, description, userId):
        self.name = name
        self.description = description
        self.userId = userId




with app.app_context():
    db.create_all()



@app.route("/")
def index():
    return "this is the home page"



@app.route("/auth/register", methods=['POST'])
def register():
    if request.method == "POST":
        firstname = request.json.get("firstname")
        lastname = request.json.get("lastname")
        password = request.json.get("password")
        email = request.json.get("email")
        phone = request.json.get("phone")

        if not firstname:
            return jsonify({"errors" : [{
                "field": "form",
                "message": "firstname field is empty"}]}),422
        elif not lastname:
            return jsonify({"errors" : [{
                "field": "form",
                "message": "lastname field is empty"}]}),422
        elif not email:
            return jsonify({"errors" : [{
                "field": "form",
                "message": "email field is empty"}]}),422
        elif not phone:
            return jsonify({"errors" : [{
                "field": "form",
                "message": "phone field is empty"}]}),422
        elif not password:
            return jsonify({"errors" : [
                {
                    "field": "password", 
                    "message": "password field is empty"
                }]}),422
        users = db.session.query(USERS).all()
        for user in users:
            if user.email == email:
                return jsonify({"errors" : [
            {
                "field" : "account",
                "message" : "account already exists"
            }
        ] }),422
        
        hash_password = generate_password_hash(password)
        try:
            user = USERS(firstName=firstname, lastName=lastname, email=email, phone=phone, password=hash_password)
            db.session.add(user)
            db.session.commit()
            
            try:
                org = ORGANISATION(name = f"{firstname}'s Organisation", description="users organisation", userId=user.userId)
                db.session.add(org)
                db.session.commit()
            except:
                return "organisation error"
        except:
            return jsonify({
                "status": "Bad request",
                "message": "Registration failed",
                "statusCode": "400"
            }),400
        token = create_access_token(identity={"user": user.email})  
        return jsonify({
            "status": "success",
            "message" : "registration successful",
            "statusCode": "201",
            "data": {
                "accessToken": token,
                "user": {
                    "userId": user.userId,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "email": user.email,
                    "phone": user.phone
                }
            }
        }),201
        



@app.route("/auth/login", methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.json.get('email',None)
        password = request.json.get('password',None)
        if not email:
            return jsonify({"errors" : [{
             "field": "form",
             "message": "email field is empty"}]}),422
        elif not password:
            return jsonify({"errors" : [{
             "field": "form",
             "message": "password field is empty"}]}),422
        users = db.session.query(USERS).all()
        for user in users:
            if user.email == email and check_password_hash(user.password, password) == True:
                token = create_access_token(
                    identity={
                        "user": user.email, 
                        "id": user.userId
                        })
                return jsonify({
                    "status": "success",
                    "message" : "registration successful",
                    "statusCode": "200",
                    "data": {
                        "accessToken": token,
                        "user": {
                            "userId": user.userId,
                            "firstName": user.firstName,
                            "lastName": user.lastName,
                            "email": user.email,
                            "phone": user.phone
                        }
                    }
                }),200
    
        return jsonify({
            "status": "Bad request",
            "message": "Registration successful",
            "statusCode": "401"
            }),401
    


@app.route("/api/users/:id")
@jwt_required()
def get_user():
    try:
        userId = get_jwt_identity()
        print(userId)
        print(userId['id'])
        user_id = userId['id']
        users = db.session.query(USERS).all()
        for user in users:
            if user.userId == user_id:
                return jsonify({
                    "status": "success",
                    "message": "data collected",
                    "data": {
                        "userId": user.userId,
                        "firstName": user.firstName,
                        "lastName": user.lastName,
                        "email": user.email,
                        "phone": user.phone
                    }
                }),200
    except:
        return jsonify({
            "status": "invald token"
        })



@app.route("/api/organisations", methods=["GET"])
@jwt_required()
def get_organisations():
    try:
        userId = get_jwt_identity()
        organisation_list = []
        print(userId)
        print(userId['id'])
        user_id = userId['id']
        organizations = db.session.query(ORGANISATION).all()
        for org in organizations:
            if org.userId == user_id:
                organisation_list.append(
                    {
                        "orgId": org.orgId,
                        "name" : org.name,
                        "description" : org.description
                    }
                )
        return jsonify(
            {
                "status": "success",
                "message": "data collected",
                "data": {
                    "organisation": organisation_list
                }
            }
        ),200
    except:
        return jsonify({"message": "invalid token"}),401



@app.route("/api/organisations/:orgId")
@jwt_required()
def get_organisation_by_id():
    try:
        userId = get_jwt_identity()
        user_id = userId['id']
        organizations = db.session.query(ORGANISATION).all()
        for org in organizations:
            if org.userId == user_id:
                return jsonify(
            {
                "status": "success",
                "message": "data collected",
                "data": {
                    "orgId": org.orgId,
                    "name" : org.name,
                    "description" : org.description
                }
            }
        ),200      
    except:
        return jsonify({"message": "invalid token"}),401



@app.route("/api/organisation", methods=["POST"])
@jwt_required()
def create_organisation():
    if request.method == "POST":
        name = request.json.get("name")
        description = request.json.get("description")
        if not name:
            return jsonify({
                "status": "Bad Request",
                "message": "Client error",
                "statusCode": 400
            }),400
        userId = get_jwt_identity()
        user_id = userId['id']
        try:
            org = ORGANISATION(name = name, description = description, userId=user_id)
            db.session.add(org)
            db.session.commit()
        except:
            return jsonify({
                "status": "Bad Request",
                "message": "Client error",
                "statusCode": 400
            }),400
        return jsonify({
            "status": "success",
            "message": "Organisation created successfully",
            "data": {
                "orgId": org.orgId,
                "name" : org.name,
                "description" : org.description
            }
        })
        


@app.route("/api/organisations/:orgId/users", methods=["POST"])
def add_user_to_organisation():
    if request.method == "POST":
        userId = request.json.get("userId")
        if not userId:
            return jsonify({
                "status": "Bad Request",
                "message": "invalid user ID"
            }),400
        return jsonify(
            {
                "status": "success",
                "message": "User added to organisation successfully",
            }
        ),200



if __name__ == "__main__":
    app.run(debug=True)
