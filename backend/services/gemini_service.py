"""
Multi-LLM AI Fallback Service & Threat Fusion Engine
Implements strict priority fallback cascade:
  1. Groq (openai/gpt-oss-20b or fast open-weights LLMs)
  2. Google Gemini (gemini-3.6-flash)
  3. NVIDIA NIM (meta/llama-3.2-11b-vision-instruct)
  4. Local ML Ensemble (XGBoost + LightGBM + DistilBERT)
"""

import os
import json
import re
import httpx
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_API_KEY_FALLBACK = os.getenv("GROQ_API_KEY_FALLBACK")
GROQ_KEYS = [k for k in [GROQ_API_KEY, GROQ_API_KEY_FALLBACK] if k]

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")



logger = logging.getLogger(__name__)


def clean_json_response(raw_text: str) -> Optional[Dict[str, Any]]:
    """Robustly extract and clean JSON from LLM outputs (handles <think> tags, markdown fences, etc.)"""
    if not raw_text or not isinstance(raw_text, str):
        return None
    try:
        # Strip thinking tags if generated
        text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL)
        # Strip markdown fences
        text = text.replace("```json", "").replace("```", "").strip()
        # Find json object boundaries
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end >= start:
            text = text[start:end + 1]
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception as e:
        logger.debug(f"JSON parsing error: {e} on text snippet: {raw_text[:120]}")
    return None


async def classify_with_groq(email_text: str) -> Optional[Dict[str, Any]]:
    """Priority 1: Groq API (tries primary key, then fallback account key if rate limited or failed)"""
    if not GROQ_KEYS:
        return None
    url = "https://api.groq.com/openai/v1/chat/completions"
    prompt = (
        f'Analyze this email and classify it. Respond ONLY in JSON:\n'
        f'{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}\n\n'
        f'Email:\n{email_text[:3000]}'
    )
    payload = {
        "model": "openai/gpt-oss-20b",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 250,
        "temperature": 0.1
    }

    for key_idx, key in enumerate(GROQ_KEYS):
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"]
                    parsed = clean_json_response(content)
                    if parsed and "category" in parsed:
                        parsed["provider"] = "groq"
                        parsed["model"] = "openai/gpt-oss-20b"
                        return parsed
                else:
                    logger.warning(f"Groq (key {key_idx+1}) failed status={resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            logger.warning(f"Groq (key {key_idx+1}) request error: {e}")
    return None



async def classify_with_gemini(email_text: str) -> Optional[Dict[str, Any]]:
    """Priority 2: Google Gemini (gemini-3.6-flash)"""
    if not GEMINI_API_KEY:
        return None
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={GEMINI_API_KEY}"
    prompt = (
        f'Analyze this email and classify it. Respond ONLY in JSON:\n'
        f'{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}\n\n'
        f'Email:\n{email_text[:3000]}'
    )
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                headers={"Content-Type": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    # Find first text part
                    for p in parts:
                        if "text" in p:
                            parsed = clean_json_response(p["text"])
                            if parsed and "category" in parsed:
                                parsed["provider"] = "gemini"
                                parsed["model"] = "gemini-3.6-flash"
                                return parsed
            else:
                logger.warning(f"Gemini classification failed status={resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"Gemini classification request error: {e}")
    return None


async def classify_with_nvidia(email_text: str) -> Optional[Dict[str, Any]]:
    """Priority 3: NVIDIA NIM (meta/llama-3.2-11b-vision-instruct)"""
    if not NVIDIA_API_KEY:
        return None
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    prompt = (
        f'Analyze this email and classify it. Respond ONLY in JSON:\n'
        f'{{"category": "Phishing|Spam|Legitimate|Suspicious", "reason": "brief explanation", "confidence": 0.0-1.0}}\n\n'
        f'Email:\n{email_text[:3000]}'
    )
    headers = {
        "Authorization": f"Bearer {NVIDIA_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "meta/llama-3.2-11b-vision-instruct",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 250,
        "temperature": 0.1
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                parsed = clean_json_response(content)
                if parsed and "category" in parsed:
                    parsed["provider"] = "nvidia"
                    parsed["model"] = "meta/llama-3.2-11b-vision-instruct"
                    return parsed
            else:
                logger.warning(f"NVIDIA classification failed status={resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"NVIDIA classification request error: {e}")
    return None


async def classify_email_nlp(email_text: str) -> dict:
    """
    Unified Multi-LLM API cascade classifier:
      1. Groq
      2. Gemini
      3. NVIDIA NIM
      4. Fallback default if all external APIs are unreachable/exhausted
    """
    # 1. Try Groq
    res = await classify_with_groq(email_text)
    if res:
        return res

    # 2. Try Gemini
    res = await classify_with_gemini(email_text)
    if res:
        return res

    # 3. Try NVIDIA
    res = await classify_with_nvidia(email_text)
    if res:
        return res

    # 4. Fallback
    logger.info("All LLM providers exhausted; falling back to heuristic/ML pipeline")
    return {
        "category": "Unknown",
        "reason": "External LLM APIs currently unavailable; falling back to local ML ensemble",
        "confidence": 0.0,
        "provider": "ml_ensemble_fallback"
    }


async def analyze_threat_fusion(analysis_data: dict) -> dict:
    """
    Fuse ML prediction + threat intel + geo + forensic into AI-enhanced assessment
    using multi-LLM fallback: Groq -> Gemini -> NVIDIA.
    """
    data_str = json.dumps(analysis_data, indent=2, default=str)[:4000]
    prompt = (
        f'You are a cybersecurity threat analyst. Analyze this email threat data and provide an enhanced risk assessment.\n\n'
        f'Data:\n{data_str}\n\n'
        f'Respond ONLY in JSON:\n'
        f'{{"summary": "one paragraph threat summary", "enhanced_risk_score": 0-100, "key_findings": ["finding1", "finding2"], "recommendations": ["action1", "action2"]}}'
    )

    # 1. Try Groq (iterating keys)
    for key_idx, key in enumerate(GROQ_KEYS):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={
                        "model": "openai/gpt-oss-20b",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 400,
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    parsed = clean_json_response(resp.json()["choices"][0]["message"]["content"])
                    if parsed and "summary" in parsed:
                        parsed["provider"] = "groq"
                        return parsed
        except Exception as e:
            logger.warning(f"Groq threat fusion failed (key {key_idx+1}): {e}")


    # 2. Try Gemini
    if GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={GEMINI_API_KEY}"
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                    headers={"Content-Type": "application/json"}
                )
                if resp.status_code == 200:
                    candidates = resp.json().get("candidates", [])
                    if candidates:
                        for p in candidates[0].get("content", {}).get("parts", []):
                            if "text" in p:
                                parsed = clean_json_response(p["text"])
                                if parsed and "summary" in parsed:
                                    parsed["provider"] = "gemini"
                                    return parsed
        except Exception as e:
            logger.warning(f"Gemini threat fusion failed: {e}")

    # 3. Try NVIDIA
    if NVIDIA_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    "https://integrate.api.nvidia.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {NVIDIA_API_KEY}", "Content-Type": "application/json"},
                    json={
                        "model": "meta/llama-3.2-11b-vision-instruct",
                        "messages": [
                            {"role": "system", "content": "You are a cybersecurity AI. Respond ONLY with valid raw JSON."},
                            {"role": "user", "content": prompt}
                        ],
                        "max_tokens": 400,
                        "temperature": 0.1
                    }
                )
                if resp.status_code == 200:
                    parsed = clean_json_response(resp.json()["choices"][0]["message"]["content"])
                    if parsed and "summary" in parsed:
                        parsed["provider"] = "nvidia"
                        return parsed
        except Exception as e:
            logger.warning(f"NVIDIA threat fusion failed: {e}")

    return {'summary': 'Automated heuristic & ML forensic analysis complete.', 'enhanced_risk': None}

