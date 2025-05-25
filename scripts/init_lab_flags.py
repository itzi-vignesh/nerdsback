import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nerdslab.settings')
django.setup()

from nerdslab.models import LabFlag

def init_lab_flags():
    # Clear existing flags
    LabFlag.objects.all().delete()

    # Define lab flags
    lab_flags = [
        {
            'lab_id': 'feedme',
            'flag_format': 'FLAG-{XSS-STORED-VULNERABILITY-LAB2}',
            'flag_value': 'FLAG-{XSS-STORED-VULNERABILITY-LAB2}'
        },
        {
            'lab_id': 'mediconnect',
            'flag_format': 'NERD{sql1nj3cti0n_v1a_d4t3_f0rm4t}',
            'flag_value': 'NERD{sql1nj3cti0n_v1a_d4t3_f0rm4t}'
        }
    ]

    # Create lab flags
    for flag_data in lab_flags:
        LabFlag.objects.create(**flag_data)
        print(f"Created flag for {flag_data['lab_id']}")

if __name__ == '__main__':
    print("Initializing lab flags...")
    init_lab_flags()
    print("Done!") 