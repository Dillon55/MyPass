import logging
import bcrypt
from .db_connection import get_users_collection, get_passwords_collection
from uuid import uuid4
import random
import string
import datetime
from django.core.mail import send_mail
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import traceback
import os

logger = logging.getLogger(__name__)

class VaultUser:

    def __init__(self):
        self.collection = get_users_collection()
        self.collection.create_index('username', unique=True)
        self.collection.create_index('email', unique=True)
        
        
    
      #This method generates a encryption key and using the salt and the master password
    def generate_key(self, master_password, salt):
       #Transform the master password into an encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
        return key
        #This method encrypts a password using a random salt and the master password
    def encrypt_password(self, password, master_password):
        try:
            #Generate a random salt
            salt = os.urandom(16)
            #Generate key with the random salt
            key = self.generate_key(master_password, salt)
            #Encrypt the password
            f = Fernet(key)
            encrypted = f.encrypt(password.encode('utf-8'))
            #Seperate the salt from encrypted password : 
            result = base64.b64encode(salt).decode('utf-8') + ":" + encrypted.decode('utf-8')
            return result
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise Exception(f"Failed to encrypt password: {str(e)}")
        #decrypt a password using the master password and salt
    def decrypt_password(self, encrypted_password, master_password):
       
        try:
            #Convert to string if bytes
            if isinstance(encrypted_password, bytes):
                encrypted_password = encrypted_password.decode('utf-8')
            
            #Split the salt and the encrypted data
            salt_b64, encrypted_data = encrypted_password.split(":", 1)
            salt = base64.b64decode(salt_b64)
            
            #Generate key with the stored salt
            key = self.generate_key(master_password, salt)
            
            #Decrypt with the derived key
            f = Fernet(key)
            decrypted = f.decrypt(encrypted_data.encode('utf-8'))
                
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise Exception(f"Failed to decrypt password: {str(e)}")
        #create user method using bcrypt to store hash password
    def create_user(self, username, email, password):
        try:
            username = username.lower()
            email = email.lower()

            if self.collection.find_one({'username': username}):
                return {'success': False, 'error': 'Username already exists'}
            if self.collection.find_one({'email': email}):
                return {'success': False, 'error': 'Email already registered'}

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            self.collection.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
            })
            return {'success': True}
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return {'success': False, 'error': 'An error occurred while creating the user'}

    def generate_2fa_code(self, username):
     #Generate a 2FA code a static 2FA code is generated for tes_user for testing perpose

     if username == "test_user":
        code = "123456"
       
        expiry = datetime.datetime.now() + datetime.timedelta(days=365 * 10)  #10 years
     else:
        code = ''.join(random.choices(string.digits, k=6))
        expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

     #Update the user's document with the code and expiry
     self.collection.update_one(
        {'username': username},
        {'$set': {
            '2fa_code': code,
            '2fa_expiry': expiry,
        }}
    )

     return code


    def verify_2fa_code(self, username, code):
     #Verify the 2FA code entered by the user
     user = self.collection.find_one({'username': username})
    
     if not user:
        return {'success': False, 'error': 'User not found'}
    
     #Check if code exists and is not expired
     if '2fa_code' not in user or '2fa_expiry' not in user:
        return {'success': False, 'error': 'No 2FA code was generated'}
    
     #Check if code is expired
     now = datetime.datetime.now()
     if now > user['2fa_expiry']:
        return {'success': False, 'error': 'Code has expired, please request a new one'}
    
     #Check if code matches
     if user['2fa_code'] != code:
        return {'success': False, 'error': 'Invalid code'}
    
    
     self.collection.update_one(
        {'username': username},
        {'$unset': {'2fa_code': '', '2fa_expiry': ''}}
     )
    
     return {'success': True}

    def send_2fa_email(self, username):
     #Send the 2FA code to the user's email

     
     username = username.strip().lower()

     
     user = self.collection.find_one({'username': username})
    
     if not user:
        return {'success': False, 'error': 'User not found'}
    
     email = user.get('email')
     if not email:
         return {'success': False, 'error': 'No email found for user'}

     #Generate a 2FA code (static for 'test_user')
     if username == 'test_user':
        code = '123456'
        expiry = datetime.datetime.now() + datetime.timedelta(days=365 * 10)  
     else:
        code = ''.join(random.choices(string.digits, k=6))
        expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

     
     self.collection.update_one(
        {'username': username},
        {'$set': {
            '2fa_code': code,
            '2fa_expiry': expiry,
        }}
     )

     

     
     try:
        send_mail(
            subject='Your Password Vault Verification Code',
            message=f'Your verification code is: {code}\n\nThis code will expire soon.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        return {'success': True}
     except Exception as e:
        logger.error(f"Error sending 2FA email: {e}")
        return {'success': False, 'error': f'Failed to send email: {str(e)}'}

    
    
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
            group_data = {'group_id': group_id, 'name': group_name, 'passwords': []}
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

    def delete_group(self, username, group_id):
        try:
            user = self.collection.find_one({'username': username})
            if not user:
                return {'success': False, 'error': 'User not found'}

            group = next((g for g in user.get('groups', []) if g['group_id'] == group_id), None)
            if not group:
                return {'success': False, 'error': 'Group not found'}

            result = self.collection.update_one(
                {'username': username},
                {'$pull': {'groups': {'group_id': group_id}}}
            )
            if result.modified_count > 0:
                return {'success': True}
            return {'success': False, 'error': 'Failed to delete group'}
        except Exception as e:
            logger.error(f"Error deleting group: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {'success': False, 'error': 'An error occurred while deleting the group'}

    def add_password(self, username, service_name, username_name, password, master_password=None, group_id=None):
        try:
            encrypted_password = self.encrypt_password(password, master_password)
            password_id = str(uuid4())
            password_data = {
                '_id': password_id,
                'username': username,
                'service_name': service_name,
                'username_name': username_name,
                'password': encrypted_password,
                'group_id': group_id
            }
            passwords_collection = get_passwords_collection()
            passwords_collection.insert_one(password_data)

            if group_id:
                self.collection.update_one(
                    {'username': username, 'groups.group_id': group_id},
                    {'$push': {'groups.$.passwords': password_id}}
                )
            return {'success': True}
        except Exception as e:
            logger.error(f"Error adding password: {e}")
            return {'success': False, 'error': f'An error occurred: {str(e)}'}

    def delete_password(self, username, password_id):
        try:
            passwords_collection = get_passwords_collection()
            password_entry = passwords_collection.find_one({'_id': password_id, 'username': username})
            if not password_entry:
                return {'success': False, 'error': 'Password not found or unauthorized'}
            passwords_collection.delete_one({'_id': password_id})
            return {'success': True}
        except Exception as e:
            logger.error(f"Error deleting password: {e}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': 'An error occurred while deleting the password'}

    def edit_password(self, username, password_id, new_service_name, new_username_name, new_password, master_password=None):
     try:
        passwords_collection = get_passwords_collection()
        password_entry = passwords_collection.find_one({'_id': str(password_id), 'username': username})
        if not password_entry:
            return {'success': False, 'error': 'Password not found or unauthorized'}

        update_data = {
            'service_name': new_service_name,
            'username_name': new_username_name,
        }

        # Check if password change is requested and valid
        if new_password and new_password != "******":
            if not master_password:
                return {'success': False, 'error': 'Master password required to change password'}

            # Encrypt new password with master password
            encrypted_password = self.encrypt_password(new_password, master_password)
            update_data['password'] = encrypted_password

        # Perform update
        result = passwords_collection.update_one({'_id': str(password_id)}, {'$set': update_data})

        if result.modified_count == 0:
            return {'success': True, 'message': 'No changes made.'}

        return {'success': True, 'message': 'Password updated successfully.'}

     except Exception as e:
        logger.error(f"Error editing password: {e}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': 'An error occurred while updating the password'}


    @staticmethod
    def get_group_by_id(user, group_id):
        return next((group for group in user.get('groups', []) if group['group_id'] == group_id), None)

    @staticmethod
    def get_group_password_data(group_password_ids):
        passwords_collection = get_passwords_collection()
        group_password_data = []
        for password_id in group_password_ids:
            password = passwords_collection.find_one({'_id': str(password_id)})
            if password:
                group_password_data.append({
                    'password_id': str(password['_id']),
                    'service_name': password.get('service_name'),
                    'username_name': password.get('username_name'),
                    'password': password.get('password')
                })
        return group_password_data

    @staticmethod
    def get_user_passwords(username):
        passwords_collection = get_passwords_collection()
        return [
            {**password, 'id': str(password['_id'])}
            for password in passwords_collection.find({'username': username})
        ]

    @staticmethod
    def update_group_passwords(username, group_id, updated_group_password_ids):
     try:
        users_collection = get_users_collection()
        result = users_collection.update_one(
            {'username': username, 'groups.group_id': group_id},
            {'$set': {'groups.$.passwords': updated_group_password_ids}}
        )
        if result.modified_count == 0:
            return {'success': False, 'error': 'No changes made or group not found.'}
        return {'success': True}
     except Exception as e:
        logger.error(f"Error updating group passwords: {e}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': 'An error occurred while updating the group passwords.'}
