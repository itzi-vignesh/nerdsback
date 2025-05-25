"""
This module has been deprecated.
Lab operations now connect directly to Server 2 (labs.nerdslab.in/api).
Frontend applications should use the lab service API directly instead of proxying through Server 1.
"""

def get_lab_service_url():
    """Return the URL for the new lab service API"""
    return 'https://labs.nerdslab.in/api/'