package trustgw

import future.keywords.if

default allow := false

scanner_clean      if { input.scores.scanner == 0 }
signed             if { input.signatures.valid == true }
sbom_ok            if { input.sbom.present == true; input.sbom.artifact_digest == input.artifact.sha256 }
slsa_ok            if { input.provenance.slsa_level >= 3; input.provenance.builder_id != "" }
provenance_binds   if { input.provenance.artifact_sha256 == input.artifact.sha256 }
no_post_install    if { not input.package.has_post_install }
no_native_or_allow if { not input.package.has_native_loader; not input.package.native_loader_allowed }
model_ops_ok       if { not input.model.has_disallowed_ops; not input.model.has_custom_ops }
sandbox_clean      if { input.sandbox.net_calls == 0; input.sandbox.exec_calls == 0 }

allow if {
  signed
  sbom_ok
  slsa_ok
  provenance_binds
  scanner_clean
  sandbox_clean
  no_post_install
  no_native_or_allow
  model_ops_ok
}
