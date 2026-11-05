"""Rebuild the committed, manually curated catalog. Does not scrape or invent CVEs."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://securitylab.github.com/advisories/"
cases = []


def case(identifier, repo, ref, split, group, report, rows, notes=""):
    labels = []
    for ghsl, title, mechanism, location in rows:
        labels.append({
            "id": ghsl, "title": title, "mechanism": mechanism,
            "location_hint": location,
            "evidence_required": [
                "Identify the attacker-controlled input or capability and relevant preconditions.",
                "Trace that input to the affected operation using concrete repository locations.",
                "Explain the absent or ineffective defense and the resulting security consequence.",
                mechanism,
            ],
            "source": BASE + report + "/", "validation": "advisory_only",
            "fix_commit": None, "introducing_commit": None,
        })
    cases.append({"id": identifier, "repository": repo, "ref": ref,
                  "mode": "snapshot", "split": split, "leakage_group": group,
                  "validation": "advisory_only", "labels": labels, "notes": notes})


case("t001", "FlowiseAI/Flowise", "flowise@1.4.3", "dev", "flowise",
     "GHSL-2023-232_GHSL-2023-234_Flowise", [
    ("GHSL-2023-232", "Arbitrary file read", "The openai-assistants-file endpoint joins an untrusted fileName to its storage directory without enforcing containment, enabling reads outside that directory.", "packages/server/src/index.ts: /api/v1/openai-assistants-file"),
    *[(f"GHSL-2023-{n}", "Reflected XSS", f"The {endpoint} endpoint reflects an attacker-controlled identifier into an HTML error response without encoding, allowing script execution under the report's configuration assumptions.", f"packages/server/src/index.ts: {endpoint}") for n, endpoint in [(245,"/api/v1/chatflows/:id"),(246,"/api/v1/public-chatflows/:id"),(247,"/api/v1/chatflows-streaming/:id"),(248,"/api/v1/credentials/:id")]],
    ("GHSL-2023-234", "CORS misconfiguration", "An arbitrary website can read responses from an unauthenticated Flowise instance under the report's deployment assumptions because unrestricted CORS allows cross-origin reads; wildcard CORS alone is not sufficient evidence.", "packages/server/src/index.ts: cors middleware"),
], "The report does not establish a complete fixed revision. Six GHSL findings, not six independent mechanisms.")

case("t002", "datahub-project/datahub", "v0.8.44", "holdout", "datahub",
     "GHSL-2022-076_GHSL-2022-083_DataHub", [
    ("GHSL-2022-076", "Proxy SSRF/XSS", "Frontend proxy URI construction permits an attacker to change the destination host; the report also documents an XSS interpretation of this issue.", "controllers.Application#proxy"),
    ("GHSL-2022-077", "Open redirect", "An attacker-controlled redirect destination permits navigation to an untrusted site through the frontend.", "frontend redirect handling"),
    ("GHSL-2022-078", "Missing JWT signature verification", "With metadata-service authentication enabled, the backend accepts JWT identity claims without checking their cryptographic signature, enabling impersonation.", "GMS JWT authentication"),
    ("GHSL-2022-079", "System account impersonation", "In the default unauthenticated metadata-service configuration, NoOpAuthenticator trusts the caller's X-DataHub-Actor header for authorization identity.", "NoOpAuthenticator"),
    ("GHSL-2022-080", "JSON injection", "Frontend string-formatted JSON incorporates attacker-controlled values, allowing injected fields to shadow trusted fields.", "frontend JSON construction"),
    ("GHSL-2022-081", "Authentication fails open", "An erroneous JAAS configuration causes authentication to accept arbitrary credentials rather than rejecting login.", "JAAS authentication initialization"),
    ("GHSL-2022-082", "Insecure secret encryption", "SecretUtils and SecretService encrypt secrets with AES ECB, revealing repeated-block structure; explain the confidentiality consequence rather than claiming arbitrary decryption.", "SecretUtils / SecretService"),
    ("GHSL-2022-083", "Session survives logout", "Logout clears the browser cookie without invalidating its server acceptance, allowing a retained session cookie to remain usable.", "frontend logout and session verification"),
    ("GHSL-2022-086", "Untrusted deserialization", "The affected pac4j dependency deserializes attacker-controlled nonce data, creating the reported untrusted deserialization path.", "pac4j nonce handling and dependency version"),
    ("GHSL-2022-087", "Cypher injection", "Attacker-controlled data reaches Cypher query construction in Neo4JGraphService through API endpoints, enabling unintended graph queries.", "Neo4JGraphService"),
], "Ten numbered issues in the report body; the title's range is incomplete. Report says fixes were published with v0.8.45; per-issue fix mapping is not yet verified.")

case("t003", "MarkUsProject/Markus", "v2.4.6", "holdout", "markus",
     "GHSL-2024-060_GHSL-2024-068_MarkUs", [
    *[(f"GHSL-2024-{n:03}", "Arbitrary file write", f"Untrusted path data from {loc} reaches filesystem writes outside the intended repository directory; arbitrary Ruby writes can lead to delayed code execution under the documented permissions.", loc) for n,loc in [(60,"SubmissionsController#update_files"),(62,"AutomatedTestsController"),(63,"StarterFileGroupsController"),(64,"StarterFileGroupsController API")]],
    *[(f"GHSL-2024-{n:03}", "Path traversal / file read", f"An attacker-controlled path in {loc} reaches a file download without effective containment, enabling unintended file reads under the documented account permissions.", loc) for n,loc in [(65,"AutomatedTestsController#download_file"),(66,"ExamTemplatesController#download_error_file"),(67,"ExamTemplatesController#download_generate"),(68,"StarterFileGroupsController#download")]],
], "GHSL-2024-061 was withdrawn as a duplicate sink and is excluded.")

case("t004", "owen2345/camaleon-cms", "2.8.0", "dev", "camaleon",
     "GHSL-2024-182_GHSL-2024-186_Camaleon_CMS", [
    ("GHSL-2024-182", "Arbitrary file write to RCE", "An ordinary authenticated user's upload folder and format options reach the local uploader without containment, enabling arbitrary file writes and delayed Ruby execution where filesystem permissions permit.", "MediaController#upload -> CamaleonCmsLocalUploader#add_file"),
    ("GHSL-2024-183", "Path traversal", "An ordinary authenticated user's file parameter reaches send_file through download_private_file without enforcing the private-media root.", "MediaController#download_private_file"),
    ("GHSL-2024-184", "Stored XSS", "An ordinary user can upload active SVG or HTML content served under the application's origin, enabling script execution when another user views it.", "MediaController upload and media serving"),
    ("GHSL-2024-185", "Code injection", "An administrator can enable label_eval and supply custom field text evaluated as Ruby; the report chains this with account takeover, so administrator prerequisites must be stated.", "custom field rendering: label_eval / eval"),
    ("GHSL-2024-186", "Arbitrary file deletion", "An administrator-controlled folder parameter reaches the local uploader deletion operation without containment; do not describe this as an unauthenticated deletion.", "MediaController#actions -> CamaleonCmsLocalUploader#delete_file"),
], "Report identifies 2.8.1 as containing fixes; individual fix commits and safe controls remain unverified.")

case("t005", "RVC-Project/Retrieval-based-Voice-Conversion-WebUI", "2.2.231006", "dev", "voice-conversion",
     "GHSL-2025-012_GHSL-2025-022_Retrieval-based-Voice-Conversion-WebUI", [
    *[(f"GHSL-2025-{n:03}", "Command injection", f"User-supplied UI parameters reach shell command construction in {loc}, permitting command execution when an untrusted caller can invoke the UI.",loc) for n,loc in [(12,"infer-web.py: preprocess_dataset"),(13,"infer-web.py: extract_f0_feature"),(14,"infer-web.py: click_train")]],
    ("GHSL-2025-015", "Code injection", "A user-controlled checkpoint path selects a train.log file whose contents are passed to eval; establish control of that file's content before claiming code execution.", "infer-web.py: change_info_"),
    *[(f"GHSL-2025-{n:03}", "Unsafe model deserialization", f"A user-controlled model path reaches unsafe torch.load in {loc}; establish that an attacker can supply the serialized artifact and state the applicable runtime assumptions.",loc) for n,loc in [(16,"process_ckpt.py: show_info"),(17,"process_ckpt.py: extract_small_model"),(18,"process_ckpt.py: change_info"),(19,"process_ckpt.py: merge"),(20,"export.py: export_onnx"),(21,"vr.py: AudioPre"),(22,"vr.py: AudioPreDeEcho")]],
], "Report does not identify a complete fixed revision. Shares model-loading code with GPT-SoVITS: keep in the same split.")

case("t006", "RVC-Boss/GPT-SoVITS", "20250228v3", "dev", "voice-conversion",
     "GHSL-2025-045_GHSL-2025-048_RVC-Boss_GPT-SoVITS", [
    *[(f"GHSL-2025-{n:03}", "Command injection", f"User-supplied paths or parameters flow into shell=True command construction in {loc}, allowing command execution when an untrusted user can invoke the UI.",loc) for n,loc in [(45,"webui.py: open_slice"),(46,"webui.py: open_denoise"),(47,"webui.py: open_asr"),(48,"webui.py: change_label")]],
], "Report does not establish a complete fixed revision. Model deserialization findings use a second report.")

# Preserve separate provenance for the five deserialization findings.
for n,loc in [(49,"vr.py: AudioPre"),(50,"vr.py: AudioPreDeEcho"),(51,"bsroformer.py: Roformer_Loader"),(52,"inference_webui.py: change_gpt_weights"),(53,"process_ckpt.py: load_sovits_new")]:
    cases[-1]["labels"].append({
        "id": f"GHSL-2025-{n:03}", "title": "Unsafe model deserialization",
        "mechanism": "An attacker-supplied model artifact reaches unsafe torch.load through a user-controlled model path; establish artifact control and the runtime's deserialization behavior.",
        "location_hint": loc,
        "evidence_required": ["Establish attacker control of the model artifact.", "Trace the artifact to the specific unsafe deserialization call.", "Explain execution consequences and runtime preconditions."],
        "source": BASE + "GHSL-2025-049_GHSL-2025-053_RVC-Boss_GPT-SoVITS/",
        "validation": "advisory_only", "fix_commit": None, "introducing_commit": None,
    })

data = {"schema_version": 1, "name": "ghsl-six-repos-v1", "cases": cases,
        "status": "snapshot_detection_seed", "label_provenance": "Manually paraphrased from seven public GitHub Security Lab reports. Not independently exploit-validated.",
        "limitations": ["Positive-only snapshot tasks do not measure PR introduction attribution or false-positive rate.", "Public advisory labels are incomplete: unmatched findings require adjudication.", "Refs must be resolved to immutable commits by prepare before running.", "Development and held-out groups were selected before any agent run; no performance results exist."]}
path = ROOT / "secbench/data/catalog.json"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {len(cases)} cases / {sum(len(c['labels']) for c in cases)} labels")
