from django.core.management.base import BaseCommand
from nerdslab.models import LabFlag

class Command(BaseCommand):
    help = 'Initialize lab flags in the database'

    def handle(self, *args, **options):
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
            self.stdout.write(
                self.style.SUCCESS(f"Created flag for {flag_data['lab_id']}")
            ) 