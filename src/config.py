MONGO_URI = f'mongodb://external.abriment.com:32390,external.abriment.com:30911/'
MONGO_AUTH_DB = "incidents_db"
MONGO_DB = "incidents_db" 
MONGO_USERNAME = "admin"
MONGO_PASSWORD = "SAra@131064"

DB_USERNAME = 'postgres'
DB_PASSWORD = 'SAra%40131064'
DB_HOST = 'external.abriment.com'
DB_PORT = 30455
DB_DATABASE = 'postgres'
DB_URI = f'postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{str(DB_PORT)}/{DB_DATABASE}'

REDIS_HOST = 'external.abriment.com'
REDIS_PORT = 30057
REDIS_USERNAME = 'default'
REDIS_PASSWORD = 'SAra@131064'

INITIAL_ADMIN_PASSWORD = 'SAra@131064'
APP_SECRET_KEY = 'CoMplExP@s3w0Rd'