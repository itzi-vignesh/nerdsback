import os
from django.conf import settings

# CDN Settings
CDN_URL = os.getenv('CDN_URL', 'https://cdn.nerdslab.in')
STATIC_CDN_URL = os.getenv('STATIC_CDN_URL', 'https://static.nerdslab.in')
MEDIA_CDN_URL = os.getenv('MEDIA_CDN_URL', 'https://media.nerdslab.in')

# Static files configuration
STATIC_URL = f'{STATIC_CDN_URL}/static/'
STATIC_ROOT = os.path.join(settings.BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files configuration
MEDIA_URL = f'{MEDIA_CDN_URL}/media/'
MEDIA_ROOT = os.path.join(settings.BASE_DIR, 'media')

# Whitenoise configuration
WHITENOISE_USE_FINDERS = True
WHITENOISE_MANIFEST_STRICT = False
WHITENOISE_ALLOW_ALL_ORIGINS = True
WHITENOISE_INDEX_FILE = True 