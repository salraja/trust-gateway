package main

import (
  "bytes"
  "crypto/sha256"
  "encoding/hex"
  "encoding/json"
  "io"
  "log"
  "mime/multipart"
  "net/http"
  "os"
  "os/exec"
  "path/filepath"
  "time"
)

type ScanResult struct{ Score float64 `json:"score"`; Reasons []string `json:"reasons"` }
type ModelScanResult struct {
  Score float64 `json:"score"`; Reasons []string `json:"reasons"`
  HasDisallowedOps bool `json:"has_disallowed_ops"`
  HasCustomOps bool `json:"has_custom_ops"`
  OpsList []string `json:"ops_list"`
}
type SandResp struct{ Syscalls []string `json:"syscalls"`; FileWrites []string `json:"file_writes"`; NetCalls,ExecCalls,ExitCode,DurationMs int }
type Decision struct {
  Decision string `json:"decision"`; Scores map[string]float64 `json:"scores"`
  PoliciesTriggered []string `json:"policies_triggered"`; WaiverID *string `json:"waiver_id"`
  SignedValid bool `json:"signed_valid"`; SbomPresent bool `json:"sbom_present"`
  SlsaLevel int `json:"slsa_level"`; BuilderID string `json:"builder_id"`; AttArtifact string `json:"att_artifact_sha256"`
}

func health(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Content-Type","application/json"); io.WriteString(w, `{"status":"ok"}`) }

func postFile(url, field, filename string) (*http.Response, error) {
  var b bytes.Buffer
  mw := multipart.NewWriter(&b)
  fw, _ := mw.CreateFormFile(field, filepath.Base(filename))
  f, err := os.Open(filename); if err != nil { return nil, err }
  defer f.Close()
  if _, err := io.Copy(fw, f); err != nil { return nil, err }
  mw.Close()
  req, _ := http.NewRequest("POST", url, &b)
  req.Header.Set("Content-Type", mw.FormDataContentType())
  client := &http.Client{ Timeout: 60 * time.Second }
  return client.Do(req)
}

func runSandbox(url, filename string) (*SandResp, error) {
  resp, err := postFile(url, "file", filename); if err != nil { return nil, err }
  defer resp.Body.Close()
  var s SandResp
  if err := json.NewDecoder(resp.Body).Decode(&s); err != nil { return nil, err }
  return &s, nil
}

func callPkgScanner(url, filename string) (*ScanResult, error) {
  resp, err := postFile(url, "file", filename); if err != nil { return nil, err }
  defer resp.Body.Close()
  var r ScanResult
  if err := json.NewDecoder(resp.Body).Decode(&r); err != nil { return nil, err }
  return &r, nil
}

func callModelScanner(url, filename string) (*ModelScanResult, error) {
  resp, err := postFile(url, "file", filename); if err != nil { return nil, err }
  defer resp.Body.Close()
  var r ModelScanResult
  if err := json.NewDecoder(resp.Body).Decode(&r); err != nil { return nil, err }
  return &r, nil
}

func sha256File(path string) (string, error) {
  f, err := os.Open(path); if err != nil { return "", err }
  defer f.Close()
  h := sha256.New()
  if _, err := io.Copy(h, f); err != nil { return "", err }
  return hex.EncodeToString(h.Sum(nil)), nil
}

func run(cmd string, args ...string) (string, error) {
  c := exec.Command(cmd, args...); c.Env = os.Environ()
  out, err := c.CombinedOutput()
  if err != nil { return string(out), err }
  return string(out), nil
}

func verify(w http.ResponseWriter, r *http.Request) {
  if err := r.ParseMultipartForm(64<<20); err != nil { http.Error(w, err.Error(), 400); return }
  kind := r.FormValue("type")

  file, _, err := r.FormFile("file"); if err != nil { http.Error(w, "missing file", 400); return }
  defer file.Close()

  var sigPath string
  if sig, _, _ := r.FormFile("sig"); sig != nil {
    defer sig.Close()
    sp, _ := os.CreateTemp("", "sig-*.sig"); io.Copy(sp, sig); sp.Close()
    sigPath = sp.Name()
  }

  slsaLevel := 0
  builderID := ""
  attArtifact := ""
  if att, _, _ := r.FormFile("att"); att != nil {
    defer att.Close()
    var a struct{ SlsaLevel int `json:"slsa_level"`; BuilderID string `json:"builder_id"`; ArtifactSHA256 string `json:"artifact_sha256"` }
    _ = json.NewDecoder(att).Decode(&a)
    slsaLevel = a.SlsaLevel; builderID = a.BuilderID; attArtifact = a.ArtifactSHA256
  }

  tmpf, _ := os.CreateTemp("", "art-*"); io.Copy(tmpf, file); tmpf.Close()
  artPath := tmpf.Name()
  artifactSHA, _ := sha256File(artPath)

  pkgURL := getenv("PKG_SCANNER", "http://127.0.0.1:8081/scan/package")
  modelURL := getenv("MODEL_SCANNER", "http://127.0.0.1:8082/scan/model")
  sandURL := getenv("SANDBOX", "http://127.0.0.1:8083/sandbox/run")

  // scanners
  var scanScore float64
  hasDisallowedOps := false
  hasCustomOps := false
  if kind == "model" {
    ms, err := callModelScanner(modelURL, artPath)
    if err != nil { http.Error(w, "scanner error: "+err.Error(), 500); return }
    scanScore = ms.Score
    hasDisallowedOps = ms.HasDisallowedOps
    hasCustomOps = ms.HasCustomOps
  } else {
    ps, err := callPkgScanner(pkgURL, artPath)
    if err != nil { http.Error(w, "scanner error: "+err.Error(), 500); return }
    scanScore = ps.Score
  }

  sres, err := runSandbox(sandURL, artPath); if err != nil { http.Error(w, "sandbox error: "+err.Error(), 500); return }

  // signature
  sigValid := false
  pub := getenv("COSIGN_PUBLIC_KEYS_PATH", "infra/trust/cosign.pub")
  if sigPath != "" {
    if _, err := os.Stat(pub); err == nil {
      _, err := run("cosign", "verify-blob", "--key", pub, "--signature", sigPath, artPath)
      sigValid = (err == nil)
    }
  }

  // sbom
  sbomPresent := false
  if _, err := exec.LookPath("syft"); err == nil {
    _, err := run("syft", "-q", "-o", "spdx-json=/dev/stdout", artPath)
    sbomPresent = (err == nil)
  }

  // OPA input
  input := map[string]any{
    "artifact": map[string]any{ "sha256": artifactSHA, "type": kind },
    "signatures": map[string]any{ "valid": sigValid },
    "provenance": map[string]any{
      "slsa_level": slsaLevel, "builder_id": builderID, "artifact_sha256": attArtifact,
    },
    "sbom": map[string]any{ "present": sbomPresent, "artifact_digest": artifactSHA },
    "package": map[string]any{ "has_post_install": false, "has_native_loader": false, "native_loader_allowed": false },
    "model": map[string]any{ "has_disallowed_ops": hasDisallowedOps, "has_custom_ops": hasCustomOps },
    "sandbox": map[string]any{ "net_calls": sres.NetCalls, "exec_calls": sres.ExecCalls },
    "scores": map[string]any{ "scanner": scanScore },
  }

  inbytes, _ := json.Marshal(input)
  cmd := exec.Command("opa", "eval", "-I", "-f", "json", "-d", "policies/policy.rego", "data.trustgw.allow")
  cmd.Stdin = bytes.NewReader(inbytes)
  outOPA, err := cmd.Output(); if err != nil { http.Error(w, "opa eval error: "+err.Error(), 500); return }

  var or struct{ Result []struct{ Expressions []struct{ Value bool `json:"value"` } `json:"expressions"` } `json:"result"` }
  if err := json.Unmarshal(outOPA, &or); err != nil { http.Error(w, "opa parse error", 500); return }
  decision := "block"
  if len(or.Result) > 0 && len(or.Result[0].Expressions) > 0 && or.Result[0].Expressions[0].Value { decision = "allow" }

  w.Header().Set("Content-Type","application/json")
  json.NewEncoder(w).Encode(Decision{
    Decision: decision,
    Scores: map[string]float64{"scanner": scanScore},
    PoliciesTriggered: []string{}, WaiverID: nil,
    SignedValid: sigValid, SbomPresent: sbomPresent,
    SlsaLevel: slsaLevel, BuilderID: builderID, AttArtifact: attArtifact,
  })
}

func getenv(k, def string) string { if v := os.Getenv(k); v != "" { return v }; return def }

func main() {
  http.HandleFunc("/health", health)
  http.HandleFunc("/verify", verify)
  log.Println("gateway :8080")
  log.Fatal(http.ListenAndServe(":8080", nil))
}
