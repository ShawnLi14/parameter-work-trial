"""Materialize PR cases from real upstream commit pairs listed in a reviewed manifest.

Every entry is re-checked here: the pair must really be parent and child, the diff
must be substantive and in bounds, and each quoted evidence line must exist at the
stated commit. Exploitability is not established by these checks; see each entry's
review record. No upstream code is executed.
"""
import copy
import hashlib
from pathlib import Path
import re

from .catalog import POSITIVE_VARIANTS, CONTROL_VARIANTS, digest, validate
from .runner import git, read_json, write_json

CONSTRUCTION = {"introduced_historical": "historical_commit_pair", "fix_reverted": "fix_reverted",
                "security_fix": "historical_commit_pair", "benign_nearby": "historical_commit_pair",
                "preexisting_touch": "historical_commit_pair"}
MAX_FILES, MAX_LINES = 70, 7000
COMMENT = re.compile(r"^(#|//|/\*|\*|<!--|--)")
# Changelogs name the advisory a fix addresses, which would hand a reviewer the answer;
# a reversed fix would even show the entry being deleted. They are left out of every diff.
HIDDEN = (":(exclude,glob,icase)**/changelog*",)
# Vendored libraries, lockfiles, and minified or snapshot files are not reviewable code; a
# single vendored library can be megabytes. They are left out of diffs and size counts.
NOT_REVIEWED = HIDDEN + tuple(f":(exclude,glob)**/{pattern}" for pattern in (
    "vendor/**", "node_modules/**", "third_party/**", "bower_components/**",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock", "poetry.lock",
    "*.min.js", "*.min.css", "*.snap"))


def opaque_order(entries):
    """Order by content hash so case numbering reveals nothing about the variant."""
    return sorted(entries, key=lambda e: hashlib.sha256(f"pr-v2|{e['base_commit']}|{e['head_commit']}".encode()).hexdigest())


def changed_code_lines(diff):
    """Added or removed lines that are not blank and not plainly comments."""
    lines = []
    for line in diff.splitlines():
        if line[:1] in ("+", "-") and not line.startswith(("+++", "---")):
            body = line[1:].strip()
            if body and not COMMENT.match(body):
                lines.append(line)
    return lines


def diff_stats(repo, base, head):
    files, lines = 0, 0
    for row in git("-C", repo, "diff", "--numstat", "--no-renames", base, head, "--", ".", *NOT_REVIEWED).decode("utf-8", "replace").splitlines():
        added, deleted, path = row.split("\t", 2)
        files += 1
        if added != "-":
            lines += int(added) + int(deleted)
    return files, lines


def file_contains(repo, commit, path, string):
    """Whether the file exists at commit and, when a string is given, contains it."""
    try:
        blob = git("-C", repo, "show", f"{commit}:{path}").decode("utf-8", "replace")
    except ValueError:
        return False
    return string is None or " ".join(string.split()) in " ".join(blob.split())


def check_entry(repo, entry):
    """Raise ValueError unless the pair and its evidence hold in the fetched history."""
    base, head, name = entry["base_commit"], entry["head_commit"], entry["candidate_id"]
    if entry["kind"] not in CONSTRUCTION:
        raise ValueError(f"{name}: unknown kind {entry['kind']}")
    child, parent = (base, head) if entry["kind"] == "fix_reverted" else (head, base)
    if git("-C", repo, "rev-parse", child + "^1").decode().strip() != parent:
        raise ValueError(f"{name}: {parent} is not the first parent of {child}")
    diff = git("-C", repo, "diff", "--no-color", "--no-ext-diff", "--no-renames", base, head, "--", ".", *NOT_REVIEWED)
    files, lines = diff_stats(repo, base, head)
    if not 0 < files <= MAX_FILES or lines > MAX_LINES:
        raise ValueError(f"{name}: diff out of bounds ({files} files, {lines} lines)")
    if not changed_code_lines(diff.decode("utf-8", "replace")):
        raise ValueError(f"{name}: diff changes no code; comment-only controls are not accepted")
    is_positive = entry["kind"] in POSITIVE_VARIANTS
    label_ids = entry["label_ids"]
    if is_positive != bool(label_ids):
        raise ValueError(f"{name}: positives need labels, controls must not have any")
    if len(set(label_ids)) != len(label_ids):
        raise ValueError(f"{name}: repeated label")
    for item in entry["evidence"]:
        if item["commit"] not in {base, head}:
            raise ValueError(f"{name}: evidence cites a commit outside this pair")
        blob = git("-C", repo, "show", f"{item['commit']}:{item['path']}").decode("utf-8", "replace")
        if " ".join(item["quote"].split()) not in " ".join(blob.split()):
            raise ValueError(f"{name}: quote not found in {item['path']} at {item['commit'][:12]}")
    for claim in entry.get("absence_claims", []):
        if claim["commit"] not in {base, head}:
            raise ValueError(f"{name}: absence claim cites a commit outside this pair")
        if file_contains(repo, claim["commit"], claim["path"], claim.get("string")):
            raise ValueError(f"{name}: claimed absent but present in {claim['path']} at {claim['commit'][:12]}")
    for label_id in label_ids:
        if not any(i["commit"] == head and i.get("label_id") == label_id for i in entry["evidence"]):
            raise ValueError(f"{name}: {label_id} needs its own evidence at head")
        if not (entry.get("mechanism_at_commit") or {}).get(label_id):
            raise ValueError(f"{name}: {label_id} needs a mechanism at this commit")
    if entry["review"]["verdict"] != "confirmed":
        raise ValueError(f"{name}: only confirmed entries may be built")
    if not is_positive and entry.get("also_valid"):
        raise ValueError(f"{name}: a control with a known issue is not a control")
    return diff, files, lines


def fetch(repository, repo, commit):
    """Fetch the child commit and its parents; no prior clone or full history is needed."""
    if not repo.exists():
        repo.mkdir(parents=True)
        git("init", "--bare", repo)
    git("-C", repo, "fetch", "--depth=2", "--no-tags", f"https://github.com/{repository}.git", commit)


def build(data, manifest, cache, destination, check_only=False):
    destination, cache = Path(destination).resolve(), Path(cache).resolve()
    if destination.exists() and not check_only:
        raise ValueError("PR destination already exists; choose a fresh --out directory")
    source_cases = {c["id"]: c for c in data["cases"]}
    labels = {l["id"]: l for c in data["cases"] for l in c["labels"]}
    suite = {"schema_version": 1, "name": manifest["name"], "status": "historical_commit_pairs",
             "label_provenance": manifest["label_provenance"], "limitations": manifest["limitations"], "cases": []}
    prepared = []
    for index, entry in enumerate(opaque_order(manifest["entries"]), 1):
        source = source_cases[entry["snapshot_case"]]
        repo = cache / (source["id"] + ".git")
        child = entry["base_commit"] if entry["kind"] == "fix_reverted" else entry["head_commit"]
        fetch(source["repository"], repo, child)
        diff, files, lines = check_entry(repo, entry)
        # Fetched commits have no reference by default, so Git's cleanup could delete them.
        for commit in (entry["base_commit"], entry["head_commit"]):
            git("-C", repo, "update-ref", f"refs/secbench/{commit}", commit)
        case = {"id": f"h{index:03}", "repository": source["repository"], "ref": entry["head_commit"],
                "base_ref": entry["base_commit"], "mode": "pr", "split": source["split"],
                "leakage_group": source["leakage_group"], "validation": "source_reviewed",
                "construction": CONSTRUCTION[entry["kind"]], "variant": entry["kind"], "labels": [],
                "candidate_id": entry["candidate_id"], "upstream_pr": entry.get("upstream_pr"),
                "files_changed": files, "lines_changed": lines, "confidence": entry["confidence"],
                "caveats": entry.get("caveats", ""), "control_scope": "this_diff_only",
                "also_valid": [dict(item, id=f"av{i}") for i, item in enumerate(entry.get("also_valid", []), 1)]}
        if entry["kind"] in POSITIVE_VARIANTS:
            for label_id in entry["label_ids"]:
                label = copy.deepcopy(labels[label_id])
                label["mechanism"] = entry["mechanism_at_commit"][label_id]
                label["evidence_required"].append("Explain why the proposed diff introduces the issue relative to base.")
                if entry["kind"] == "fix_reverted":
                    label["fix_commit"] = entry["base_commit"]
                else:
                    label["introducing_commit"] = entry["head_commit"]
                case["labels"].append(label)
        elif entry["kind"] not in CONTROL_VARIANTS:
            raise ValueError(f"unknown variant {entry['kind']}")
        suite["cases"].append(case)
        prepared.append((case, repo, diff))
    validate(suite)  # Everything has been checked before anything is written.
    if check_only:
        return suite
    destination.mkdir(parents=True)
    catalog_digest = digest(suite)
    for case, repo, diff in prepared:
        head_dir, base_dir = destination / "sources" / case["id"], destination / "bases" / case["id"]
        patch = destination / "diffs" / (case["id"] + ".patch")
        patch.parent.mkdir(exist_ok=True)
        body = diff.decode("utf-8", "replace").encode("utf-8")
        patch.write_bytes(body)
        write_json(destination / "locks" / (case["id"] + ".json"), {
            "case_id": case["id"], "repository": case["repository"], "commit": case["ref"],
            "base_commit": case["base_ref"], "source_dir": str(head_dir), "base_source_dir": str(base_dir),
            "on_demand": True, "store": str(repo),
            "patch_sha256": hashlib.sha256(body).hexdigest(), "catalog_sha256": catalog_digest})
    write_json(destination / "catalog.json", suite)
    write_json(destination / "freeze.json", {"catalog_sha256": catalog_digest, "catalog": suite})
    return suite


def coverage(data, manifest):
    """Account for every catalog target: covered by a PR, or unusable with a reason."""
    covered = {}
    for entry in manifest["entries"]:
        for label_id in entry["label_ids"]:
            if label_id in covered:
                raise ValueError(f"{label_id} is covered by more than one PR")
            covered[label_id] = entry["candidate_id"]
    unusable = {u["label_id"]: u["reason"] for u in manifest.get("unusable_targets", [])}
    targets = {l["id"] for c in data["cases"] for l in c["labels"]}
    if set(covered) & set(unusable):
        raise ValueError("a target is listed as both covered and unusable")
    return {"target_count": len(targets), "covered": len(covered), "unusable": unusable,
            "unaccounted": sorted(targets - set(covered) - set(unusable))}


def load_manifest(path):
    manifest = read_json(path)
    pairs = [(e["base_commit"], e["head_commit"]) for e in manifest["entries"]]
    if len(set(pairs)) != len(pairs):
        raise ValueError("manifest repeats a commit pair")
    return manifest
