import httpx, os

BASE="http://127.0.0.1"
def test_pkg_benign():
    with open("datasets/benign/benign_pkg.py","rb") as f:
        r = httpx.post(f"{BASE}:8081/scan/package", files={"file":("benign.py", f)})
        r.raise_for_status()
        j = r.json(); assert j["score"] == 0.0

def test_pkg_malicious():
    with open("datasets/malicious/pkg_postinstall.py","rb") as f:
        r = httpx.post(f"{BASE}:8081/scan/package", files={"file":("m.py", f)})
        r.raise_for_status()
        j = r.json(); assert j["score"] == 1.0
        assert "POST_INSTALL" in " ".join(j["reasons"])

def test_model_benign():
    with open("datasets/benign/benign_model.onnxmeta","rb") as f:
        r = httpx.post(f"{BASE}:8082/scan/model", files={"file":("b.onnxmeta", f)})
        r.raise_for_status()
        assert r.json()["score"] == 0.0

def test_model_malicious():
    with open("datasets/malicious/model_badops.onnxmeta","rb") as f:
        r = httpx.post(f"{BASE}:8082/scan/model", files={"file":("m.onnxmeta", f)})
        r.raise_for_status()
        j = r.json(); assert j["score"] == 1.0
        assert any("bad_op:" in x or "custom_ops" in x for x in j["reasons"])
