#!/usr/bin/env python3
"""
Gmail OAuth2 Authentication Script
Run this once to generate token.pickle for Gmail API access
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

BASE_DIR = Path(__file__).parent
CREDENTIALS_PATH = BASE_DIR / "credentials" / "credentials.json"
TOKEN_PATH = BASE_DIR / "credentials" / "token.pickle"

def authenticate():
    """Authenticate and save token"""
    if not CREDENTIALS_PATH.exists():
        print(f"[ERROR] Credentials file not found: {CREDENTIALS_PATH}")
        print("Please place your credentials.json in backend/credentials/")
        return False
    
    print("[AUTH] Starting Gmail OAuth2 authentication...")
    print(f"[INFO] Credentials: {CREDENTIALS_PATH}")
    print(f"[INFO] Token will be saved to: {TOKEN_PATH}")
    print()
    print("A browser window will open. Please sign in and grant access.")
    print("If browser does not open, copy the URL manually.")
    print()
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_PATH), SCOPES)
        creds = flow.run_local_server(port=0, open_browser=True, timeout=120)
        
        # Save token
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(TOKEN_PATH, 'wb') as token:
            import pickle
            pickle.dump(creds, token)
        
        print()
        print("[SUCCESS] Authentication successful!")
        print(f"[INFO] Token saved to: {TOKEN_PATH}")
        
        # Print refresh token for Render deployment
        print()
        print("=" * 60)
        print("FOR RENDER DEPLOYMENT - Copy this value:")
        print("=" * 60)
        print(f"GMAIL_REFRESH_TOKEN={creds.refresh_token}")
        print("=" * 60)
        print()
        
        # Test connection
        from googleapiclient.discovery import build
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        print(f"[INFO] Connected Gmail: {profile['emailAddress']}")
        print(f"[INFO] Total messages: {profile['messagesTotal']}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        print()
        print("[HELP] Common issues:")
        print("  - Port already in use (try closing other apps)")
        print("  - Firewall blocking localhost")
        print("  - Network timeout")
        return False

if __name__ == '__main__':
    success = authenticate()
    sys.exit(0 if success else 1)
