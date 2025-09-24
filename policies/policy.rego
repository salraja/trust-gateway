package trustgw

import future.keywords.if

default allow := false

dev_ok if { input.dev_mode == true }

# gates/thresholds
scanner_clean if { input.scores.scanner == 0 }
signed        if { input.signatures.valid == true }
sbom_ok       if { input.sbom.present == true; input.sbom.artifact_digest == input.artifact.sha256 }
no_post_install if { not input.package.has_post_install }
no_native_or_allow if { not input.package.has_native_loader; not input.package.native_loader_allowed }
model_ops_ok  if { not input.model.has_disallowed_ops; not input.model.has_custom_ops }
sandbox_clean if { input.sandbox.net_calls == 0; input.sandbox.exec_calls == 0 }

# Dev-mode allow (kept for convenience; gateway sets dev_mode=false)
allow if { dev_ok }

# TEMP production allow (signature + SBOM + scanners + sandbox + basic pkg/model gates)
allow if {
  signed
  sbom_ok
  scanner_clean
  sandbox_clean
  no_post_install
  no_native_or_allow
  model_ops_ok
}
