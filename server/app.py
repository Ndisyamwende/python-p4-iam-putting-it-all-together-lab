#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from config import app, db, api, bcrypt
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json_data = request.get_json()
        
        username = json_data.get('username')
        password = json_data.get('password')
        
        if not username or not password:
            return {'message': 'Username and password are required'}, 400
        
        try:
            hashed_password = generate_password_hash(password)
            user = User(username=username, _password_hash=hashed_password)
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            
            return user.to_dict(), 201
        
        except IntegrityError:
            return {'message': 'Username already exists'}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        else:
            return {}, 401

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        
        username = json_data.get('username')
        password = json_data.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'message': 'Invalid credentials'}, 401

class Logout(Resource):
    def post(self):
        session.pop('user_id', None)
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'message': 'Unauthorized. Please login to create a recipe.'}, 401
        
        json_data = request.get_json()
        
        title = json_data.get('title')
        instructions = json_data.get('instructions')
        minutes_to_complete = json_data.get('minutes_to_complete')
        
        if not title or not instructions or not minutes_to_complete:
            return {'message': 'Title, instructions, and minutes_to_complete are required.'}, 422
        
        try:
            recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete, user_id=user_id)
            db.session.add(recipe)
            db.session.commit()
            
            return {
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': recipe.user.to_dict()
            }, 201
        
        except IntegrityError:
            return {'message': 'Error saving recipe.'}, 422
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)