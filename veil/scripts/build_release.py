#!/usr/bin/env python3
"""Reproducible release build script for Veil Agent (Task 4 & DONE WHEN check).
Builds Chrome and Firefox MV3 release zips.
Enforces that:
1. All test-only flags (TEST_DISABLE_GATE, etc.) are stripped or absent.
2. No evaluation data, test files, .env, or debug endpoints exist in the zip.
3. Every file inside the release archive is grepped for forbidden test/debug strings.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VEIL_DIR = os.path.dirname(SCRIPT_DIR)
EXTENSION_DIR = os.path.join(VEIL_DIR, "extension")
DIST_DIR = os.path.join(VEIL_DIR, "dist")

FORBIDDEN_GREP_PATTERNS = [
    r"__TEST_DISABLE_GATE",
    r"TEST_DISABLE_GATE",
    r"/canary/register",
    r"/canary/report",
    r"canary_field_hits",
    r"canary_registry"
]

FORBIDDEN_FILE_PATTERNS = [
    r"\.env",
    r"\.test\.js$",
    r"eval[/\\]",
    r"corpus[/\\]",
    r"test_",
    r"\.git"
]


def clean_content(content: str, is_gate_file: bool = False) -> str:
    """Strips test-only negative control code from release files."""
    if is_gate_file:
        # Strip negative control test flag declaration
        content = re.sub(r"\s*// Negative control test flag[^\n]*\n\s*let __TEST_DISABLE_GATE = false;\s*", "\n", content)
        # Strip conditional test check around assertClean
        content = re.sub(
            r"if \(!__TEST_DISABLE_GATE\) \{\s*assertClean\(payload\);[^\}]*\}",
            "assertClean(payload);",
            content
        )
        # Strip test hooks from exported object
        content = re.sub(r"\s*setTestDisableGate:[^\n]+,?", "", content)
        content = re.sub(r"\s*isTestDisableGate:[^\n]+,?", "", content)
    return content


def build_package(target: str = "chrome") -> str:
    os.makedirs(DIST_DIR, exist_ok=True)
    zip_path = os.path.join(DIST_DIR, f"veil-{target}.zip")
    if os.path.exists(zip_path):
        os.remove(zip_path)

    # Read base manifest
    manifest_path = os.path.join(EXTENSION_DIR, "manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if target == "firefox":
        # Firefox MV3 background script adjustment
        manifest["background"] = {
            "scripts": ["background/orchestrator.js"]
        }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Write modified manifest
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        zf.writestr("manifest.json", manifest_bytes)

        # Walk extension files
        for root, dirs, files in os.walk(EXTENSION_DIR):
            for file in files:
                if file == "manifest.json":
                    continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, EXTENSION_DIR)

                # Check forbidden file patterns
                for pat in FORBIDDEN_FILE_PATTERNS:
                    if re.search(pat, rel_path, re.IGNORECASE):
                        raise RuntimeError(f"Forbidden file pattern '{pat}' detected in bundle: {rel_path}")

                is_gate = file == "gate.js"
                with open(full_path, "rb") as rf:
                    raw_data = rf.read()

                # Process text files to strip test hooks
                if file.endswith((".js", ".html", ".css", ".json")):
                    try:
                        text_data = raw_data.decode("utf-8")
                        cleaned = clean_content(text_data, is_gate_file=is_gate)
                        raw_data = cleaned.encode("utf-8")
                    except UnicodeDecodeError:
                        pass

                zf.writestr(rel_path.replace("\\", "/"), raw_data)

    return zip_path


def audit_zip(zip_path: str):
    """Deep inspects every file in the generated zip for forbidden test flags or debug hooks."""
    violations = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # Check filename
            for pat in FORBIDDEN_FILE_PATTERNS:
                if re.search(pat, info.filename, re.IGNORECASE):
                    violations.append(f"Forbidden file in zip: {info.filename}")

            # Check file contents
            if info.filename.endswith((".js", ".html", ".json", ".txt")):
                with zf.open(info) as f:
                    content = f.read().decode("utf-8", errors="replace")
                    for pat in FORBIDDEN_GREP_PATTERNS:
                        matches = re.findall(pat, content)
                        if matches:
                            violations.append(f"Forbidden pattern '{pat}' found {len(matches)}x in {info.filename}")

    if violations:
        for v in violations:
            print(f"❌ AUDIT FAILURE: {v}", file=sys.stderr)
        raise RuntimeError(f"Release audit failed with {len(violations)} violation(s)")

    # Compute SHA-256
    with open(zip_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    size_kb = os.path.getsize(zip_path) / 1024
    print(f"✔ Audit PASSED for {os.path.basename(zip_path)} ({size_kb:.1f} KB, SHA-256: {sha256[:16]}...)")
    return sha256


def main():
    print("=== Building Veil Agent Production Release Packages ===")
    chrome_zip = build_package("chrome")
    audit_zip(chrome_zip)

    firefox_zip = build_package("firefox")
    audit_zip(firefox_zip)
    print("=== All Release Packages Built & Audited Successfully ===")


if __name__ == "__main__":
    main()
