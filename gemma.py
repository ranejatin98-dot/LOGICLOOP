"""Gemma 4 layer for BUGDNA root-cause analysis and recommendations."""
import json
import os
from google import genai
from google.genai import types

MODEL = os.environ.get("BUGDNA_AI_MODEL", "gemma-4-31b-it")


def analyze_with_gemma(bug_data, deterministic_analysis):
    """Return AI root-cause analysis, or None when AI is not configured/available."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None

    client = genai.Client(api_key=api_key)

    payload = {
        "bug": bug_data,
        "deterministic_analysis": {
            "overview": deterministic_analysis.get("overview", {}),
            "fingerprint": deterministic_analysis.get("fingerprint", {}),
            "similar_bugs": deterministic_analysis.get("similar_bugs", [])[:4],
            "pattern": deterministic_analysis.get("pattern", {}),
            "root_cause": deterministic_analysis.get("root_cause", {}),
            "recommendation": deterministic_analysis.get("recommendation", {}),
        },
    }

    prompt = """You are the root-cause analysis engine inside BUGDNA, a software debugging tool.
Analyze the supplied bug and the deterministic BUGDNA evidence.

Your job is NOT to invent facts. Use the error, code, description, environment, fingerprint,
similar historical bugs, and recurring pattern as evidence.

Return ONLY valid JSON with exactly these fields:
{
  "cause": "concise likely root cause",
  "confidence": 0.0,
  "explanation": "short technical explanation connecting evidence to the cause",
  "recommendation": "best first recommendation",
  "fix_steps": ["step 1", "step 2", "step 3"]
}

Rules:
- confidence must be a number from 0.0 to 1.0.
- If evidence is incomplete, explicitly say so and lower confidence.
- Keep fix_steps practical and specific.
- Do not claim the bug is fixed.
- Do not output markdown fences or extra text.

BUGDNA DATA:
""" + json.dumps(payload, ensure_ascii=False, default=str)

    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.2,
            max_output_tokens=700,
        ),
    )

    raw = response.text or ""
    data = json.loads(raw)
    steps = data.get("fix_steps", [])
    if not isinstance(steps, list):
        steps = []
    data["fix_steps"] = [str(x) for x in steps][:6]
    data["confidence"] = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
    return {
        "cause": str(data.get("cause", "")),
        "confidence": data["confidence"],
        "explanation": str(data.get("explanation", "")),
        "recommendation": str(data.get("recommendation", "")),
        "fix_steps": data["fix_steps"],
        "model": MODEL,
        "status": "active",
    }
