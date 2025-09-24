from fastapi import FastAPI, UploadFile, File, HTTPException
from pydantic import BaseModel
import tempfile, os
import onnx

app = FastAPI()

# Disallowed ops & allowed domains policy (tune as you like)
DISALLOWED_OPS = {"Scan", "If", "Loop", "PythonOp", "Memcpy", "SystemCall"}
ALLOWED_DOMAINS = {"", "ai.onnx", "ai.onnx.ml"}

class ScanResult(BaseModel):
    score: float
    reasons: list[str]
    has_disallowed_ops: bool = False
    has_custom_ops: bool = False
    ops_list: list[str] = []

@app.get("/health")
def health():
    return {"status": "ok"}

def analyze_onnx(path: str) -> ScanResult:
    try:
        model = onnx.load(path)
    except Exception as e:
        # Not a valid ONNX — treat as suspicious but don’t crash
        return ScanResult(score=1.0, reasons=[f"onnx_load_error:{e}"], has_disallowed_ops=True)

    has_disallowed = False
    has_custom = False
    reasons: list[str] = []
    ops_seen: list[str] = []

    g = model.graph
    for n in g.node:
        op = n.op_type or ""
        dom = n.domain or ""
        ops_seen.append(f"{dom}::{op}" if dom else op)

        # custom op/domain?
        if dom not in ALLOWED_DOMAINS:
            has_custom = True
            reasons.append(f"custom_domain:{dom or 'NONE'}::{op}")

        # disallowed op?
        if op in DISALLOWED_OPS:
            has_disallowed = True
            reasons.append(f"bad_op:{op}")

    score = 1.0 if (has_disallowed or has_custom) else 0.0
    # Deduplicate reasons
    reasons = sorted(set(reasons))
    return ScanResult(
        score=score,
        reasons=reasons,
        has_disallowed_ops=has_disallowed,
        has_custom_ops=has_custom,
        ops_list=sorted(set(ops_seen)),
    )

@app.post("/scan/model", response_model=ScanResult)
async def scan_model(file: UploadFile = File(...)):
    # Save to a temp file because onnx.load expects a path/bytes-like
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name
    try:
        result = analyze_onnx(tmp_path)
        return result
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
