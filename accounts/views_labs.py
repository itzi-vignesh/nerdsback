"""
This file has been deprecated as lab operations now connect directly to Server 2.
All lab-related functionality should use the labs.nerdslab.in API directly.
"""

from rest_framework.response import Response
from rest_framework import status

def legacy_redirect_response():
    """Return a response directing clients to use the new lab service API"""
    return Response({
        "message": "Lab service has moved",
        "new_api_url": "https://labs.nerdslab.in/api/",
    }, status=status.HTTP_301_MOVED_PERMANENTLY)