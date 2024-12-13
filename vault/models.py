import logging
import bcrypt 
from .db_connection import get_users_collection, get_passwords_collection
from uuid import uuid4

logger = logging.getLogger(__name__)

class VaultUser:
    
    #storing the users
    
    
    def __init__(self):
        # Initialize the users collection
        self.collection = get_users_collection()

        # Create unique indexes for username and email
        self.collection.create_index('username', unique=True)
        self.collection.create_index('email', unique=True)




    def create_user(self, username, email, password):
        try:
            # Convert username and email to lowercase
            username = username.lower()
            email = email.lower()

            # Check if username or email already exists
            if self.collection.find_one({'username': username}):
                return {'success': False, 'error': 'Username already exists'}
            if self.collection.find_one({'email': email}):
                return {'success': False, 'error': 'Email already registered'}

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Insert the user into the database
            self.collection.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
            })
            return {'success': True}
        except Exception as e:
            
            logger.error(f"Error creating user: {e}")
            return {'success': False, 'error': 'An error occurred while creating the user'}





    

    def get_user_by_username(self, username):
        try:
            username = username.lower()
            return self.collection.find_one({'username': username})
        except Exception as e:
            logger.error(f"Error fetching user by username: {e}")
            return None
        
        
    def authenticate(self, username, password):
        user = self.collection.find_one({'username': username})
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            return user
        return None

    def create_group(self, username, group_name):
        try:
            group_id = str(uuid4())
            group_data = {
                'group_id': group_id,
                'name': group_name,
                'passwords': []  # Empty list initially
            }

            # Add the group to the user's document
            result = self.collection.update_one(
                {'username': username},
                {'$push': {'groups': group_data}}
            )
            if result.modified_count > 0:
                return {'success': True, 'group_id': group_id}
            return {'success': False, 'error': 'Failed to add group'}
        except Exception as e:
            logger.error(f"Error creating group: {e}")
            return {'success': False, 'error': 'An error occurred'}
        
    def add_password(self, username, service_name, password, group_id=None):
        try:
            password_id = str(uuid4())
            password_data = {
                '_id': password_id,
                'username': username,
                'service_name': service_name,
                'password': password,
                'group_id': group_id
            }

            # Insert password into the passwords collection
            passwords_collection = get_passwords_collection()
            passwords_collection.insert_one(password_data)

            # if a group is selected update the group
            if group_id:
                self.collection.update_one(
                    {'username': username, 'groups.group_id': group_id},
                    {'$push': {'groups.$.passwords': password_id}}
                )
            return {'success': True}
        except Exception as e:
            logger.error(f"Error adding password: {e}")
            return {'success': False, 'error': 'An error occurred'}
        



    @staticmethod
    def get_user_by_username(username):
        users_collection = get_users_collection()
        return users_collection.find_one({'username': username})

    @staticmethod
    def get_group_by_id(user, group_id):
        # Find the group within the user's groups list
        return next((group for group in user.get('groups', []) if group['group_id'] == group_id), None)

    @staticmethod
    def get_group_password_data(group_password_ids):
        # Fetch the full details of the passwords in the group by their IDs
        passwords_collection = get_passwords_collection()
        group_password_data = []
        for password_id in group_password_ids:
            password = passwords_collection.find_one({'_id': ObjectId(password_id)})
            if password:
                group_password_data.append({
                    'password_id': str(password['_id']),  # Store password_id as string
                    'service_name': password.get('service_name'),
                    'password': password.get('password')
                })
        return group_password_data

    @staticmethod
    def get_user_passwords(username):
        # Fetch the user's passwords
        passwords_collection = get_passwords_collection()
        return [
            {**password, 'id': str(password['_id'])} for password in passwords_collection.find({'username': username})
        ]

    @staticmethod
    def update_group_passwords(username, group_id, updated_group_password_ids):
        # Update the passwords for the group
        users_collection = get_users_collection()
        users_collection.update_one(
            {'username': username, 'groups.group_id': group_id},
            {'$set': {'groups.$.passwords': updated_group_password_ids}}
        )

        