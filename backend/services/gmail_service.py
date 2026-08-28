"""
Gmail API Service
OAuth2 authentication and email fetching via Gmail API
Supports both local pickle auth and env var credentials for deployment
"""

import os
import json
import pickle
import base64
import logging
from pathlib import Path
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
MAX_EMAIL_SIZE = 50000

BASE_DIR = Path(__file__).parent.parent
CREDENTIALS_PATH = BASE_DIR / "credentials" / "credentials.json"
TOKEN_PATH = BASE_DIR / "credentials" / "token.pickle"

logger = logging.getLogger(__name__)


def authenticate_gmail():
    """
    Authenticate Gmail using env vars (for deployment) or local files.
    
    Environment Variables:
        GMAIL_CREDENTIALS_JSON: Full credentials.json content as string
        GMAIL_REFRESH_TOKEN: OAuth2 refresh token
    """
    creds = None
    
    # Method 1: Environment variables (for deployment)
    credentials_json = os.getenv('GMAIL_CREDENTIALS_JSON')
    refresh_token = os.getenv('GMAIL_REFRESH_TOKEN')
    
    if credentials_json and refresh_token:
        try:
            client_secrets = json.loads(credentials_json)
            client_info = client_secrets.get('installed', client_secrets.get('web', {}))
            
            creds = Credentials(
                token=None,  # Will be refreshed
                refresh_token=refresh_token,
                token_uri=client_info.get('token_uri', 'https://oauth2.googleapis.com/token'),
                client_id=client_info.get('client_id'),
                client_secret=client_info.get('client_secret'),
                scopes=SCOPES
            )
            creds.refresh(Request())
            logger.info("Authenticated via environment variables")
            return build('gmail', 'v1', credentials=creds)
            
        except Exception as e:
            logger.error(f"Env var auth failed: {e}")
            # Fall through to local methods
    
    # Method 2: Local pickle file (for development)
    if TOKEN_PATH.exists():
        try:
            with open(TOKEN_PATH, 'rb') as token:
                creds = pickle.load(token)
        except Exception:
            creds = None
    
    # Method 3: Interactive OAuth flow (first time local setup)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None
        else:
            if not CREDENTIALS_PATH.exists():
                raise FileNotFoundError(
                    "Gmail credentials not found. Set GMAIL_CREDENTIALS_JSON and "
                    "GMAIL_REFRESH_TOKEN environment variables, or place credentials.json "
                    f"at {CREDENTIALS_PATH}"
                )
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_PATH), SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save token for local development
        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(TOKEN_PATH, 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)


def _extract_email_body(payload: dict) -> str:
    parts = payload.get('parts', [])
    body = ''
    if parts:
        for part in parts:
            if part.get("mimeType") == 'text/html':
                data = part.get('body', {}).get('data', '')
                if data:
                    try:
                        body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        break
                    except Exception:
                        continue
        if not body:
            for part in parts:
                if part.get("mimeType") == 'text/plain':
                    data = part.get('body', {}).get('data', '')
                    if data:
                        try:
                            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            break
                        except Exception:
                            continue
    else:
        data = payload.get("body", {}).get("data", "")
        if data:
            try:
                body = base64.urlsafe_b64decode(data).decode("utf-8", errors='ignore')
            except Exception:
                pass
    return body


def _extract_email_headers(payload: dict) -> dict:
    """Extract raw headers from Gmail payload for forensic analysis"""
    headers = {}
    for header in payload.get('headers', []):
        headers[header['name']] = header['value']
    return headers


def fetch_recent_emails(limit=5, include_headers=True):
    """Fetch recent emails with full headers for forensic analysis"""
    try:
        service = authenticate_gmail()
    except Exception as e:
        logger.error(f"Gmail auth failed: {e}")
        return []

    try:
        results = service.users().messages().list(userId='me', maxResults=limit, fields='messages(id)').execute()
        message_ids = [msg['id'] for msg in results.get('messages', [])]
        if not message_ids:
            return []

        emails = []
        for msg_id in message_ids:
            try:
                msg_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
                payload = msg_data.get('payload', {})
                body = _extract_email_body(payload)
                if len(body) > MAX_EMAIL_SIZE:
                    body = body[:MAX_EMAIL_SIZE]

                soup = BeautifulSoup(body, 'html.parser')
                clean_text = soup.get_text(separator=' ', strip=True)

                email_entry = {'id': msg_id, 'body': clean_text, 'raw_body': body}
                if include_headers:
                    email_entry['headers'] = _extract_email_headers(payload)
                    # Reconstruct raw header string for forensic analyzer
                    header_str = '\n'.join(f'{k}: {v}' for k, v in email_entry['headers'].items())
                    email_entry['raw_headers'] = header_str

                if clean_text:
                    emails.append(email_entry)
            except Exception as e:
                logger.error(f"Failed to fetch {msg_id}: {e}")
                continue

        return emails
    except Exception as e:
        logger.error(f"Error fetching emails: {e}")
        return []
