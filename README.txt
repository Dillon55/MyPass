Docker is required to run this application
if you do not have docker it can be installed here: https://www.docker.com/get-started/
*****NOTE*****
2FA will not work if you want it to work make a application password on google for now change the 2fa settings in settings.py to have 
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend' and remove the rest of the gmail settings. the 2fa codes will be sent
to the console this way.

********************************************
1) -make a .env file in the project directory

   - fill the file like this for example 
   - the user and password details can be modified to what you want 

# MongoDB credentials
MONGO_USERNAME=admin
MONGO_PASSWORD=password
MONGO_DB=password_manager

# Mongo URI format for Django (uses variables above)
MONGO_URI=mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/${MONGO_DB}?authSource=admin
DJANGO_SETTINGS_MODULE=password_manager.settings


2) ensure that docker is open and running on your pc for these commands to work
type these commands into the terminal
- cd mypass
- docker-compose up -d mongo
- docker-compose up -d web
- docker exec -it mypass-mongo-1 mongosh -u admin -p password --authenticationDatabase admin
- use admin

-the user and pwd fields can be changed here to whatever you want

db.createUser({ 
user:"admin", 
pwd:"password", 
roles: [ {role: "root", db: "admin" } ]
})

-  docker-compose down 
-  docker-compose up --build

the server should be running now 
go to http://localhost:8000/ to access the site
if you want to view the database in mongodb compass 
use this connection string mongodb://admin:password@localhost:27017/password_manager?authSource=admin
replace admin:password with what ever username and password you have chosen
