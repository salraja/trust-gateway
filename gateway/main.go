package main

import (
  "bytes"
  "encoding/json"
  "io"
  "log"
  "mime/multipart"
  "net/http"
  "os"
  "os/exec"
  "time"
)

type ScanResult struct {
  Score   float64  `json:"score"`
  Reasons []string `json:"reasons"`
}
type SandResp struct {
  Syscalls   []string `json:"syscalls"`
  FileWrites []string `json:"file_writes"`
  NetCalls   int      `json:"net_calls"`
  ExecCalls  int      `json:"exec_calls"`
  ExitCode   int      `json:"exit_code"`
  DurationMs int      `json:"duration_ms"`
}
type Decision struct {
  Decision          string             `json:"decision"`
  Scores            map[string]float64 `json:"scores"`
  PoliciesTriggered []string           `json:"policies_triggered"`
  WaiverID          *string            `json:"waiver_id"`
}

func health(w http.ResponseWriter, _ *http.Request) {
  w.Header().Set("Content-Type", "application/json")
  io.WriteString(w, `{"status":"ok"}`)
}

func postFile(url, field, filename string) (*http.Response, error) {
  var b bytes.Buffer
  mw := multipart.NewWriter(&b)
  fw, _ := mw.CreateFormFile(field, filename)
  f, err := os.Open(filename)
  if err != nil { return nil, err }
  defer f.Close()
  if _, err := io.Copy(fw, f); err != nil { return nil, err }
  mw.Close()
  req, _ := http.NewRequest("POST", url, &b)
  req.Header.Set("Content-Type", mw.FormDataContentType())
  client := &http.Client{ Timeout: 60 * time.Second }
  return client.Do(req)
}

func runSandbox(url, filename string) (*SandResp, error) {
  resp, err := postFile(url, "file", filename)
  if err != nil { return nil, err }
  defer resp.Body.Close()
  var s SandResp
  if err := json.NewDecoder(resp.Body).Decode(&s); err != nil { return nil, err }
  return &s, nil
}

func callScanner(url, filename string) (*ScanResult, error) {
  resp, err := postFile(url, "file", filename)
  if err != nil { return nil, err }
  defer resp.Body.Close()
  var r ScanResult
  if err := json.NewDecoder(resp.Body).Decode(&r); err != nil { return nil, err }
  return &r, nil
}

func verify(w http.ResponseWriter, r *http.Request) {
  if err := r.ParseMultipartForm(64 << 20); err != nil {
    http.Error(w, err.Error(), 400); return
  }
  kind := r.FormValue("type")
  file, _, err := r.FormFile("file")
  if err != nil { http.Error(w, "missing file", 400); return }
  defer file.Close()

  tmp := "tmp_artifact.bin"
  out, _ := os.Create(tmp)
  io.Copy(out, file)
  out.Close()

  pkgURL := getenv("PKG_SCANNER", "http://127.0.0.1:8081/scan/package")
  modelURL := getenv("MODEL_SCANNER", "http://127.0.0.1:8082/scan/model")
  sandURL := getenv("SANDBOX", "http://127.0.0.1:8083/sandbox/run")

  var scan *ScanResult
  if kind == "model" {
    scan, err = callScanner(modelURL, tmp)
  } else {
    scan, err = callScanner(pkgURL, tmp)
  }
  if err != nil { http.Error(w, "scanner error: "+err.Error(), 500); return }

  sres, err := runSandbox(sandURL, tmp)
  if err != nil { http.Error(w, "sandbox error: "+err.Error(), 500); return }

  input := map[string]any{
    "dev_mode": false,
    "artifact": map[string]any{ "sha256": "dev", "type": kind },
    "signatures": map[string]any{ "valid": false },
    "provenance": map[string]any{ "slsa_level": 0, "builder_id": "" },
    "sbom": map[string]any{ "present": false, "artifact_digest": "dev" },
    "package": map[string]any{
      "has_post_install": false,
      "has_native_loader": false,
      "native_loader_allowed": false,
    },
    "model": map[string]any{
      "has_disallowed_ops": false,
      "has_custom_ops": false,
    },
    "sandbox": map[string]any{
      "net_calls": sres.NetCalls,
      "exec_calls": sres.ExecCalls,
    },
    "scores": map[string]any{
      "scanner": scan.Score,
    },
  }

  inbytes, _ := json.Marshal(input)
  cmd := exec.Command("opa", "eval", "-I", "-f", "json", "-d", "policies/policy.rego", "data.trustgw.allow")
  cmd.Stdin = bytes.NewReader(inbytes)
  outOPA, err := cmd.Output()
  if err != nil { http.Error(w, "opa eval error: "+err.Error(), 500); return }

  var or struct {
    Result []struct{
      Expressions []struct{ Value bool `json:"value"` } `json:"expressions"`
    } `json:"result"`
  }
  if err := json.Unmarshal(outOPA, &or); err != nil { http.Error(w, "opa parse error", 500); return }

  decision := "block"
  if len(or.Result) > 0 && len(or.Result[0].Expressions) > 0 && or.Result[0].Expressions[0].Value {
    decision = "allow"
  }

  w.Header().Set("Content-Type","application/json")
  json.NewEncoder(w).Encode(Decision{
    Decision: decision,
    Scores: map[string]float64{"scanner": scan.Score},
    PoliciesTriggered: []string{},
    WaiverID: nil,
  })
}

func getenv(k, def string) string {
  if v := os.Getenv(k); v != "" { return v }
  return def
}

func main() {
  http.HandleFunc("/health", health)
  http.HandleFunc("/verify", verify)
  log.Println("gateway :8080")
  log.Fatal(http.ListenAndServe(":8080", nil))
}
