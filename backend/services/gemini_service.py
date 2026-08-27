"""
Gemini AI Service
NLP email classification and threat fusion analysis using Google Gemini
"""

import os
import json
import httpx
import logging
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
logger = logging.getLogger(__name__)


async def classify_email_nlp(email_text: str) -> dict:
    """Classify email using Gemini NLP — returns category + reason"""
    if not GEMINI_API_KEY:
        return {'category': 'Unknown', 'reason': 'No Gemini API key', 'confidence': 0}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    prompt = f"""Analyze this email and classify it. Respond ONLY in JSON:
{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}

Email:
{email_text[:3000]}"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json={"contents": [{"parts": [{"text": prompt}]}]},
                                    headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                cleaned = text.strip().replace("```json", "").replace("```", "").strip()
                return json.loads(cleaned)
            return {'category': 'Unknown', 'reason': f'API error {resp.status_code}', 'confidence': 0}
    except Exception as e:
        logger.error(f"Gemini classification error: {e}")
        return {'category': 'Unknown', 'reason': str(e), 'confidence': 0}


async def analyze_threat_fusion(analysis_data: dict) -> dict:
    """Fuse ML prediction + threat intel + geo + forensic into AI-enhanced assessment"""
    if not GEMINI_API_KEY:
        return {'summary': 'AI enrichment unavailable', 'enhanced_risk': None}

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    prompt = f"""You are a cybersecurity threat analyst. Analyze this email threat data and provide an enhanced risk assessment.

Data:
{json.dumps(analysis_data, indent=2, default=str)[:4000]}

Respond ONLY in JSON:
{{"summary": "one paragraph threat summary", "enhanced_risk_score": 0-100, "key_findings": ["finding1", "finding2"], "recommendations": ["action1", "action2"]}}"""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json={"contents": [{"parts": [{"text": prompt}]}]},
                                    headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                cleaned = text.strip().replace("```json", "").replace("```", "").strip()
                return json.loads(cleaned)
            return {'summary': 'AI analysis failed', 'enhanced_risk': None}
    except Exception as e:
        logger.error(f"Gemini fusion error: {e}")
        return {'summary': f'AI error: {e}', 'enhanced_risk': None}
