class Configs:
    APP_NAME = "Price Hunter"
    # Database Settings;
    DB_NAME = "ph"
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_USER = ""
    DB_CODE = ""
    # Mailbox Settings;
    MAIL_DEFAULT_SENDER = ""
    MAIL_PASSWORD = ""
    MAIL_PORT = 587
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_USE_TLS = True
    MAIL_USE_SSL = True
    MAIL_USERNAME = ""
    
class Development(Configs):
    DEBUG = True
    ENV = "development"
    SECRET_KEY = ""
    TESTING = True

class Production(Configs):
    ENV = "production"
    SECRET_KEY = ""
