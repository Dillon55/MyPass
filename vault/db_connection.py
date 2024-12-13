from pymongo import MongoClient
from django.conf import settings
#connection to mongodb 
def get_database():
    
    client = MongoClient(settings.MONGO_URI)  #Use URI from settings
    return client[settings.MONGO_DB_NAME]  #Return the database from settings

#connect to the users collection
def get_users_collection():
 
    db = get_database()
    return db['users']  #return the users collection

#connect to the passwords collection
def get_passwords_collection():
    
    
    db = get_database()
    return db['passwords']  #Return the passwords collection


