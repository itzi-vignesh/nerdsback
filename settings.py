import os
import stat
from pathlib import Path
import dotenv
from datetime import timedelta
from corsheaders.defaults import default_headers

# Build paths
BASE_DIR = Path(__file__).resolve().parent

# Environment file selection with fallback logic
# Priority: DJANGO_ENV -> .env.production -> .env -> error
environment = os.getenv('DJANGO_ENV', 'production')

env_files = []
if environment == 'production':
    env_files = ['.env.production', '.env']
elif environment == 'development':
    env_files = ['.env.development', '.env']
else:
    env_files = [f'.env.{environment}', '.env']

env_file_loaded = None
for env_file in env_files:
    env_path = os.path.join(BASE_DIR, env_file)
    if os.path.exists(env_path):
        dotenv.load_dotenv(env_path)
        env_file_loaded = env_file
        print(f"Loaded environment from: {env_file}")
        break

if not env_file_loaded:
    available_files = [f for f in ['.env', '.env.production', '.env.development'] 
                      if os.path.exists(os.path.join(BASE_DIR, f))]
    raise FileNotFoundError(
        f"No environment file found for environment '{environment}'. "
        f"Tried: {', '.join(env_files)}. "
        f"Available files: {', '.join(available_files) if available_files else 'None'}"
    )

# Required environment variables
required_env_vars = [
    'DJANGO_SECRET_KEY',
    'LAB_SECRET_KEY',
    'EMAIL_HOST_USER',
    'EMAIL_HOST_PASSWORD',
]

# Validate required environment variables
missing_vars = [var for var in required_env_vars if not os.getenv(var)]
if missing_vars:
    raise ValueError(f"Missing required environment variables in .env.production: {', '.join(missing_vars)}")

# Setup logging paths properly - ensure directory exists
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Custom configuration settings
BASE_API_URL = "/api/v1/"
FRONTEND_URL = os.getenv('FRONTEND_URL', 'https://learn.nerdslab.in')

# Security settings
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
DEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'nerd-api.nerdslab.in').split(',')

# Lab environment secret key for token generation/verification
LAB_SECRET_KEY = os.getenv('LAB_SECRET_KEY')
if not LAB_SECRET_KEY:
    raise ValueError("LAB_SECRET_KEY environment variable is required. Please ensure it is set in .env.production file.")

# Token settings
TOKEN_SETTINGS = {
    'SECRET_KEY': LAB_SECRET_KEY,  # Use the LAB_SECRET_KEY from environment
    'ALGORITHM': 'HS256',
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'TOKEN_VERSION': '1.0',
    'BLACKLIST_ENABLED': True,
    'FINGERPRINT_ENABLED': True,
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'accounts.apps.AccountsConfig',
    'nerdslab.apps.NerdslabConfig',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # Must be first
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'nerdslab.middleware.SecurityHeadersMiddleware',  # Custom security headers middleware
]

# Security headers configuration
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https://*.nerdslab.in; frame-src 'self' https://*.nerdslab.in;"
}

ROOT_URLCONF = 'nerdslab.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'nerdslab.wsgi.application'

# Database settings for SQLite
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        'OPTIONS': {
            'timeout': 30,
        },
        'ATOMIC_REQUESTS': True,
    }
}

# Ensure SQLite file permissions are secure
db_path = BASE_DIR / 'db.sqlite3'
try:
    if os.path.exists(db_path):
        current_mode = stat.S_IMODE(os.stat(db_path).st_mode)
        if current_mode != 0o600:
            os.chmod(db_path, 0o600)
except Exception as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Error setting SQLite permissions: {e}")

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Password hashers
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# CORS settings
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    'https://learn.nerdslab.in',
    'https://www.learn.nerdslab.in',
    'https://lab.nerdslab.in',
    'https://nerd-api.nerdslab.in',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
] if not DEBUG else [
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://learn.nerdslab.in',
    'https://www.learn.nerdslab.in',
    'https://lab.nerdslab.in',
    'https://nerd-api.nerdslab.in',
]

# Use default headers and add our custom header
CORS_ALLOW_HEADERS = list(default_headers) + ['x-user-hash']

# Expose security headers in responses
CORS_EXPOSE_HEADERS = [
    'Content-Type',
    'X-CSRFToken',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security'
]

# CORS methods
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# CORS preflight max age
CORS_PREFLIGHT_MAX_AGE = 86400  # 24 hours

# CSRF settings
CSRF_FAILURE_VIEW = 'accounts.views.csrf_failure'
CSRF_TRUSTED_ORIGINS = CORS_ALLOWED_ORIGINS
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_USE_SESSIONS = True
CSRF_COOKIE_NAME = 'csrftoken'

# Session settings
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_NAME = 'sessionid'
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_SAVE_EVERY_REQUEST = True

# Security settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_REFERRER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_EMBEDDER_POLICY = 'require-corp'
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = 'same-site'

# Rate Limiting
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
RATE_LIMIT_PERIOD = int(os.getenv('RATE_LIMIT_PERIOD', '60'))

# Session engine - using database backend instead of Redis
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_CACHE_ALIAS = 'default'

# Cache settings
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Rate Limiting - using local memory cache
RATELIMIT_USE_CACHE = 'default'

# Email settings
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.zoho.in')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'no-reply@nerdslab.in')
EMAIL_USE_SSL = False
EMAIL_TIMEOUT = 30

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day'
    }
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': TOKEN_SETTINGS['ACCESS_TOKEN_LIFETIME'],
    'REFRESH_TOKEN_LIFETIME': TOKEN_SETTINGS['REFRESH_TOKEN_LIFETIME'],
    'ROTATE_REFRESH_TOKENS': TOKEN_SETTINGS['ROTATE_REFRESH_TOKENS'],
    'BLACKLIST_AFTER_ROTATION': TOKEN_SETTINGS['BLACKLIST_AFTER_ROTATION'],
    'UPDATE_LAST_LOGIN': TOKEN_SETTINGS['UPDATE_LAST_LOGIN'],
    
    'ALGORITHM': TOKEN_SETTINGS['ALGORITHM'],
    'SIGNING_KEY': TOKEN_SETTINGS['SECRET_KEY'],
    'VERIFYING_KEY': None,
    
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    
    'JTI_CLAIM': 'jti',
    
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': TOKEN_SETTINGS['ACCESS_TOKEN_LIFETIME'],
    'SLIDING_TOKEN_REFRESH_LIFETIME': TOKEN_SETTINGS['REFRESH_TOKEN_LIFETIME'],
}

# SMTP Settings for email functionality
SMTP_MAX_RETRIES = 3
SMTP_RETRY_DELAY = 2

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'django.log'),  # Use LOG_DIR instead of hardcoded path
            'maxBytes': 1024 * 1024 * 5,  # 5 MB
            'backupCount': 5,
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'gunicorn': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}