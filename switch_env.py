#!/usr/bin/env python
import os
import sys
import shutil

def switch_environment(env_type):
    """
    Switch between development and production environments by copying
    the appropriate .env file to the main .env file.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    if env_type not in ['local', 'production']:
        print(f"Error: Environment type must be 'local' or 'production', not '{env_type}'")
        return False
    
    # Define source and destination files
    source_file = os.path.join(base_dir, f'.env.{env_type}')
    dest_file = os.path.join(base_dir, '.env')
    
    # Check if source file exists
    if not os.path.exists(source_file):
        print(f"Error: Environment file {source_file} does not exist")
        return False
    
    # Backup current .env file if it exists
    if os.path.exists(dest_file):
        backup_file = os.path.join(base_dir, '.env.backup')
        shutil.copy2(dest_file, backup_file)
        print(f"Backed up current .env to {backup_file}")
    
    # Copy the appropriate .env file
    shutil.copy2(source_file, dest_file)
    print(f"Successfully switched to {env_type} environment")
    print(f"Copied {source_file} to {dest_file}")
    
    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python switch_env.py [local|production]")
        sys.exit(1)
    
    env_type = sys.argv[1].lower()
    if switch_environment(env_type):
        print(f"\nEnvironment switched to {env_type} mode.")
        print("Please restart your Django server for changes to take effect.")
    else:
        sys.exit(1) 