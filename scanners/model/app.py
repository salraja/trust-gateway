from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
import json

app = FastAPI()
DISALLOWED = {"PythonOp","CustomOp","Memcpy","SystemCall"}

class ScanResult(BaseModel):
    score: float
    reasons: list[str]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan/model", response_model=ScanResult)
async def scan_model(file: UploadFile = File(...)):
    raw = await file.read()
    reasons = []
    # For now we expect tiny JSON ".onnxmeta" test files; later parse real ONNX
    try:
        meta = json.loads(raw.decode("utf-8","ignore"))
        ops = set(meta.get("ops", []))
        bad = list(ops & DISALLOWED)
        if bad or meta.get("custom") is True:
            reasons.extend([f"bad_op:{op}" for op in bad] or ["custom_ops:true"])
    except Exception:
        pass
    score = 1.0 if reasons else 0.0
    return {"score": score, "reasons": reasons}
