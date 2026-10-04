import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from engine import Engine
from gemma import analyze_with_gemma


app = FastAPI(title="BUGDNA")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = Engine(os.environ.get("BUGDNA_DB", "bugdna.db"))


class BugIn(BaseModel):
    title: str = ""
    language: str = ""
    error_message: str = ""
    code: str = ""
    description: str = ""
    environment: str = ""


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "corpus": len(engine.corpus),
        "ai": bool(os.environ.get("GEMINI_API_KEY")),
        "ai_model": os.environ.get("BUGDNA_AI_MODEL", "gemma-4-31b-it"),
    }


@app.post("/api/analyze")
def analyze(b: BugIn):
    if not (
        b.error_message.strip()
        or b.title.strip()
        or b.description.strip()
    ):
        raise HTTPException(
            status_code=422,
            detail="Add at least a title, error message or description."
        )

    bug_data = b.model_dump()
    result = engine.analyze(bug_data)

    # Gemma is an additional reasoning layer. The deterministic engine,
    # fingerprint and history remain the source of the core BUGDNA analysis.
    try:
        ai = analyze_with_gemma(bug_data, result)
    except Exception as exc:
        # Never break BUGDNA just because the external AI service fails.
        ai = {
            "cause": "",
            "confidence": 0.0,
            "explanation": "",
            "recommendation": "",
            "fix_steps": [],
            "model": os.environ.get("BUGDNA_AI_MODEL", "gemma-4-31b-it"),
            "status": "offline",
            "error": str(exc)[:240],
        }

    if ai:
        result["ai_analysis"] = ai
        # Keep the original deterministic fields intact while presenting
        # Gemma's deeper reasoning in the same response.
        if ai.get("cause"):
            result["root_cause"]["ai_hypothesis"] = ai["cause"]
        if ai.get("explanation"):
            result["root_cause"]["ai_explanation"] = ai["explanation"]
        if ai.get("fix_steps"):
            result["recommendation"]["ai_steps"] = ai["fix_steps"]
        if ai.get("recommendation"):
            result["recommendation"]["ai_recommendation"] = ai["recommendation"]
    else:
        result["ai_analysis"] = {
            "status": "offline",
            "model": os.environ.get("BUGDNA_AI_MODEL", "gemma-4-31b-it"),
            "message": "Set GEMINI_API_KEY to enable Gemma 4."
        }

    return result


@app.get("/api/history")
def history():
    return engine.history()


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = BASE_DIR / "index.html"

if STATIC_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static"
    )

    @app.get("/")
    def serve_home():
        static_index = STATIC_DIR / "index.html"
        if static_index.exists():
            return FileResponse(static_index)
        if INDEX_FILE.exists():
            return FileResponse(INDEX_FILE)
        return {"error": "index.html not found"}
else:
    @app.get("/")
    def serve_home():
        if INDEX_FILE.exists():
            return FileResponse(INDEX_FILE)
        return {
            "error": "index.html not found",
            "message": "Put index.html in the same folder as main.py"
        }
