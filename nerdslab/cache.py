import os
from django.core.cache.backends.redis import RedisCache

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/{os.getenv('REDIS_DB', '0')}",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "PASSWORD": os.getenv('REDIS_PASSWORD', ''),
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
            "RETRY_ON_TIMEOUT": True,
            "MAX_CONNECTIONS": 1000,
            "CONNECTION_POOL_KWARGS": {"max_connections": 100}
        },
        "KEY_PREFIX": "nerdslab_backend"
    }
}

# Cache time to live is 1 hour
CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))

# Cache keys
CACHE_KEYS = {
    'user_profile': 'user_profile_{user_id}',
    'lab_list': 'lab_list',
    'lab_detail': 'lab_detail_{lab_id}',
    'course_list': 'course_list',
    'course_detail': 'course_detail_{course_id}',
} 