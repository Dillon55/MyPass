1) -make a .env file in the project directory

   - fill the file like this for example 
   - the user and password details can be modified to what you want 

# MongoDB credentials
MONGO_USERNAME=admin
MONGO_PASSWORD=strongpassword
MONGO_DB=password_manager

# Mongo URI format for Django (uses variables above)
MONGO_URI=mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/${MONGO_DB}?authSource=admin
DJANGO_SETTINGS_MODULE=password_manager.settings


2)
-docker-compose up -d mongo
-docker exec -it password_manager-mongo-1 mongosh
-use admin

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