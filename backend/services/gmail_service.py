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
import ssl
import tempfile
from pathlib import Path
from bs4 import BeautifulSoup
try:
    import certifi
    import httplib2
    import requests
    from google.auth.transport.requests import Request
    from google_auth_httplib2 import AuthorizedHttp
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
    Request = None
    Credentials = None
    InstalledAppFlow = None
    build = None


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
MAX_EMAIL_SIZE = 50000


class GmailAuthError(Exception):
    """Raised when Gmail credentials exist but are invalid/expired/revoked."""

BASE_DIR = Path(__file__).parent.parent
CREDENTIALS_PATH = BASE_DIR / "credentials" / "credentials.json"
TOKEN_PATH = BASE_DIR / "credentials" / "token.pickle"

logger = logging.getLogger(__name__)


def _ca_bundle_path() -> str:
    """Return Certifi roots plus Windows-trusted enterprise roots when present."""
    bundle_path = Path(tempfile.gettempdir()) / 'mailforensic-trusted-ca.pem'
    try:
        windows_roots = ssl.enum_certificates('ROOT')
        pem_roots = []
        for certificate, encoding, trust in windows_roots:
            if encoding == 'x509_asn':
                pem_roots.append(
                    '-----BEGIN CERTIFICATE-----\n'
                    + base64.encodebytes(certificate).decode('ascii')
                    + '-----END CERTIFICATE-----\n'
                )
        # Use a deterministic complete bundle so requests and httplib2 can
        # validate public CAs and organization-installed TLS proxy CAs.
        contents = Path(certifi.where()).read_text(encoding='ascii') + '\n' + ''.join(pem_roots)
        if not bundle_path.exists() or bundle_path.read_text(encoding='ascii', errors='ignore') != contents:
            bundle_path.write_text(contents, encoding='ascii')
        return str(bundle_path)
    except Exception as error:
        logger.warning('Could not read Windows trusted roots; using Certifi only: %s', error)
        return certifi.where()


def _google_request():
    """Create an authenticated request with the local trusted CA bundle."""
    session = requests.Session()
    session.verify = _ca_bundle_path()
    return Request(session=session)


def _gmail_service(creds):
    """Build Gmail API client with certificate verification explicitly configured."""
    http = httplib2.Http(ca_certs=_ca_bundle_path())
    authorized_http = AuthorizedHttp(creds, http=http)
    return build('gmail', 'v1', http=authorized_http, cache_discovery=False)


def authenticate_gmail():
    if not GOOGLE_AUTH_AVAILABLE:
        raise FileNotFoundError("Google Auth library not installed. Operating in local demo/sample mode.")
    creds = None

    
    # Method 1: Environment variables (for deployment)
    credentials_json = os.getenv('GMAIL_CREDENTIALS_JSON')
    refresh_token = os.getenv('GMAIL_REFRESH_TOKEN', '').strip()
    
    is_placeholder = not refresh_token or 'YOUR_' in refresh_token.upper() or 'CHANGE_ME' in refresh_token.upper()

    if credentials_json and refresh_token and not is_placeholder:
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
            creds.refresh(_google_request())
            logger.info("Authenticated via environment variables")
            return _gmail_service(creds)
            
        except Exception as e:
            logger.error(f"Env var auth failed: {e}")
            # Credentials are configured but unusable — surface this instead of
            # silently falling through (a dead refresh token must not read as
            # "not configured" or "0 messages").
            raise GmailAuthError(
                f"Gmail refresh token was rejected by Google ({type(e).__name__}: {str(e)[:150]}). "
                "Regenerate it by running backend/auth_gmail.py locally and updating "
                "the GMAIL_REFRESH_TOKEN environment variable."
            )
    
    # Method 2: Local pickle file (for development)
    if TOKEN_PATH.exists():
        try:
            with open(TOKEN_PATH, 'rb') as token:
                loaded = pickle.load(token)
            # Only accept a real Credentials object with a usable token.
            # A corrupt/empty pickle (e.g. a bare None) must not silently
            # fall through to an interactive OAuth flow from a request thread.
            if isinstance(loaded, Credentials) and (loaded.token or loaded.refresh_token):
                creds = loaded
            else:
                logger.warning('token.pickle exists but contains no valid credentials (%s); ignoring it', type(loaded).__name__)
                creds = None
        except Exception as e:
            logger.warning('Failed to load token.pickle (%s); ignoring it', e)
            creds = None

    # Refresh an expired token if possible
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(_google_request())
        except Exception as e:
            logger.error(f'Token refresh failed: {e}')
            creds = None

    if not creds or not creds.valid:
        raise FileNotFoundError(
            "Gmail credentials not found. Set GMAIL_CREDENTIALS_JSON and "
            "GMAIL_REFRESH_TOKEN environment variables, or place credentials.json and "
            f"a valid token.pickle at {TOKEN_PATH} (run auth_gmail.py once to generate it). "
            "Interactive OAuth cannot run inside the web server; use auth_gmail.py in a terminal."
        )

    # Save refreshed token for local development
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(TOKEN_PATH, 'wb') as token:
        pickle.dump(creds, token)

    return _gmail_service(creds)


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
    service = authenticate_gmail()

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
        # An API failure is NOT "0 messages" — surface it so the route can
        # report gmail_error instead of a misleading gmail_empty.
        raise RuntimeError(f"Gmail API error while fetching messages: {str(e)[:200]}") from e
