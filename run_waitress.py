from waitress import serve
from nerdslab.wsgi import application
import logging

logging.basicConfig(level=logging.DEBUG)  # Keep DEBUG level for more verbose output

if __name__ == '__main__':
    print('Starting Waitress server on port 8000...')
    serve(application, 
          host='127.0.0.1',  # Keep as localhost
          port=8000,
          threads=4,
          url_prefix='',
          channel_timeout=30,
          cleanup_interval=30,
          ident='NerdsLab API')