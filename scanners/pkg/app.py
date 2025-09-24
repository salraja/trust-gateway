from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel

app = FastAPI()

BAD_PATTERNS = [
    b"POST_INSTALL",             # our marker
    b"setup(",                   # crude heuristic
    b"subprocess.call(", b"os.system(", b"eval(", b"exec(",
    b"curl http://", b"wget http://", b"socket.", b"requests.get(",
    b"ctypes.CDLL(", b"cffi.FFI(",  # native loader hints
]

class ScanResult(BaseModel):
    score: float
    reasons: list[str]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan/package", response_model=ScanResult)
async def scan_package(file: UploadFile = File(...)):
    blob = await file.read()
    reasons = [p.decode("utf-8","ignore") for p in BAD_PATTERNS if p in blob]
    score = 1.0 if reasons else 0.0
    return {"score": score, "reasons": reasons}
