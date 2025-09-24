package trustgw

import future.keywords.if

default allow := false

dev_ok if { input.dev_mode == true }

# thresholds
scanner_clean if { not input.scores.scanner; input.scores.scanner == 0 }

# other gates (kept as stubs for now)
signed if { input.signatures.valid == true }
slsa_ok if { input.provenance.slsa_level >= 3; input.provenance.builder_id != "" }
sbom_ok if { input.sbom.present == true; input.sbom.artifact_digest == input.artifact.sha256 }
no_post_install if { not input.package.has_post_install }
no_native_or_allow if { not input.package.has_native_loader; not input.package.native_loader_allowed }
model_ops_ok if { not input.model.has_disallowed_ops; not input.model.has_custom_ops }
sandbox_clean if { input.sandbox.net_calls == 0; input.sandbox.exec_calls == 0 }

# Dev-mode allow (temporary)
allow if { dev_ok }

# Production allow when all clean (scanner included)
allow if {
  scanner_clean
  signed
  slsa_ok
  sbom_ok
  no_post_install
  no_native_or_allow
  model_ops_ok
  sandbox_clean
}
