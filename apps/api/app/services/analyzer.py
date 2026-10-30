import ast
import hashlib
import re
import sys
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class DetectedFinding:
    id: str
    title: str
    severity: str
    cwe: str
    path: str
    line: int
    evidence: str
    description: str
    confidence: float
    status: str = "potential"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _looks_like_sql(text: str) -> bool:
    return bool(re.search(r"\b(SELECT|UPDATE|INSERT|DELETE|WHERE|ORDER\s+BY|FROM)\b", text, re.I))


def _contains_string_build(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _is_skippable_scan_file(path: str, source: str) -> bool:
    """Check if a file should be skipped from vulnerability scanning.

    Skips:
    - Test files (test_*.py, *_test.py, tests/*, test/*)
    - Demo harnesses and proof fixtures (demo_proof.py, *_proof.py, examples/*, demos/*, fixtures/*)
    - Files with explicit intentional vulnerability fixture annotations
    """
    clean = path.replace("\\", "/").lower()
    parts = [p for p in clean.split("/") if p]
    filename = parts[-1] if parts else ""

    # Test files
    if filename.startswith("test_") or filename.endswith("_test.py"):
        return True
    if any(part in {"tests", "test", "testing", "fixtures", "fixture"} for part in parts[:-1]):
        return True

    # Demo harnesses and proof files
    if "demo_proof" in filename or filename.endswith("_proof.py"):
        return True
    if any(part in {"examples", "example", "demos", "demo", "samples", "sample"} for part in parts[:-1]):
        return True

    # Explicit marker for intentional vulnerable fixtures
    if "INTENTIONAL VULNERABILITY" in source:
        return True

    return False


def detect_sql_injection(
    files: dict[str, str],
    max_findings: int = 10,
    skip_test_files: bool = True,
) -> list[dict[str, Any]]:
    """Conservative heuristic for Python SQL strings passed to execution APIs.

    A match is a potential finding only. It does not prove exploitability.
    """
    findings: list[DetectedFinding] = []
    for path, source in files.items():
        if not path.endswith(".py"):
            continue
        if skip_test_files and _is_skippable_scan_file(path, source):
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        unsafe_vars: dict[str, tuple[int, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = getattr(node, "value", None)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if value is None or not _contains_string_build(value):
                    continue
                rendered = ast.get_source_segment(source, value) or ""
                if not _looks_like_sql(rendered):
                    # Joined string can include variable names but not SQL literal text.
                    if not isinstance(value, ast.JoinedStr) or not any(
                        isinstance(part, ast.Constant) and isinstance(part.value, str) and _looks_like_sql(part.value)
                        for part in value.values
                    ):
                        continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        unsafe_vars[target.id] = (getattr(value, "lineno", node.lineno), rendered[:300])

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else ""
            )
            if func_name not in {"execute", "executemany", "exec_driver_sql", "raw", "text"} or not node.args:
                continue
            first = node.args[0]
            candidate = False
            line = getattr(first, "lineno", node.lineno)
            evidence = ast.get_source_segment(source, first) or ""
            if _contains_string_build(first):
                candidate = _looks_like_sql(evidence) or (
                    isinstance(first, ast.JoinedStr) and any(
                        isinstance(part, ast.Constant) and isinstance(part.value, str) and _looks_like_sql(part.value)
                        for part in first.values
                    )
                )
            elif isinstance(first, ast.Name) and first.id in unsafe_vars:
                line, evidence = unsafe_vars[first.id]
                candidate = True
            if not candidate:
                continue
            fingerprint = hashlib.sha1(f"{path}:{line}:{evidence}".encode()).hexdigest()[:10]
            snippet = source.splitlines()[line - 1].strip()[:300] if 0 < line <= len(source.splitlines()) else evidence[:300]
            findings.append(DetectedFinding(
                id=f"sqli-{fingerprint}",
                title="Potential SQL injection",
                severity="high",
                cwe="CWE-89",
                path=path,
                line=line,
                evidence=snippet or evidence[:300],
                description=(
                    "SQL execution appears to receive a dynamically constructed query. If untrusted input "
                    "reaches this expression, use parameterized queries and validate the data flow. This is "
                    "a static suspicion until reproduced by a security test."
                ),
                confidence=0.78,
            ))
    # Deduplicate and cap results.
    unique: dict[tuple[str, int], DetectedFinding] = {}
    for finding in findings:
        unique[(finding.path, finding.line)] = finding
    return [item.as_dict() for item in list(unique.values())[:max_findings]]


def apply_exact_replacements(files: dict[str, str], patches: list[dict[str, str]]) -> dict[str, str]:
    """Apply model-proposed exact replacements with strict path/context checks."""
    updated = dict(files)
    for patch in patches:
        path = patch.get("path", "")
        old = patch.get("old_text", "")
        new = patch.get("new_text", "")
        if not _safe_relative_path(path):
            raise ValueError(f"Wrong path: Unsafe patch path rejected: {path}")
        if not old or not new:
            raise ValueError(f"Missing replacement text: patch for {path} must contain non-empty old_text and new_text.")
        if old == new:
            raise ValueError(f"Unchanged patch: new_text is identical to old_text for {path}.")
        if path not in updated:
            raise ValueError(f"Wrong path: patch path does not exist in repository snapshot: {path}")
        occurrences = updated[path].count(old)
        if occurrences == 0:
            raise ValueError(f"Source context mismatch: old_text was not found in {path}.")
        if occurrences > 1:
            raise ValueError(f"Non-unique match: patch context for {path} must match exactly once; found {occurrences} matches.")
        replaced = updated[path].replace(old, new, 1)
        if replaced == updated[path]:
            raise ValueError(f"Unchanged patch: applying patch produces no source change in {path}.")
        validation_error = validate_patched_python(path, updated[path], replaced)
        if validation_error:
            raise ValueError(validation_error)
        updated[path] = replaced
    return updated


def _safe_relative_path(path: str) -> bool:
    from pathlib import PurePosixPath
    p = PurePosixPath(path)
    return bool(path) and not p.is_absolute() and ".." not in p.parts and "\\" not in path and "\x00" not in path


def validate_patched_python(path: str, original: str, patched: str) -> str | None:
    """Static quality gate for Python proposals; never executes repository code.

    This only checks parseability and newly introduced references to standard-library
    module objects without a visible binding. It is not a type checker, security
    verifier, or evidence that runtime behavior is preserved.
    """
    if not path.endswith(".py"):
        return None

    try:
        patched_tree = ast.parse(patched, filename=path)
    except SyntaxError as exc:
        return f"Python syntax error: {exc.msg} (line {exc.lineno}) in {path}."

    try:
        original_tree = ast.parse(original, filename=path)
    except SyntaxError:
        original_tree = ast.Module(body=[], type_ignores=[])

    def module_attribute_roots(tree: ast.AST) -> set[str]:
        return {
            node.value.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
        }

    introduced = module_attribute_roots(patched_tree) - module_attribute_roots(original_tree)
    candidates = introduced & sys.stdlib_module_names
    if not candidates:
        return None

    bindings: set[str] = set()
    for node in ast.walk(patched_tree):
        if isinstance(node, ast.Import):
            bindings.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            bindings.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bindings.add(node.id)
        elif isinstance(node, ast.arg):
            bindings.add(node.arg)

    missing = sorted(candidates - bindings)
    if missing:
        names = ", ".join(missing)
        return (
            f"Missing Python module import: new reference(s) to {names} need an "
            f"explicit import or binding in {path}. Include imports in the patch."
        )
    return None


def validate_patch_proposal(
    proposal: Any,
    expected_path: str,
    source: str,
) -> tuple[dict[str, str] | None, str | None]:
    """Validate a patch proposal against expected path and source code.

    Returns (validated_patch, None) on success, or (None, error_diagnostic) on failure.
    Distinguishes exact rejection reasons:
    - invalid JSON
    - wrong path
    - missing replacement text
    - source context mismatch
    - non-unique match
    - unchanged patch
    """
    if not isinstance(proposal, dict):
        return None, "Invalid JSON: model output must be a valid JSON object."

    proposed_path = proposal.get("path")
    if not proposed_path or not isinstance(proposed_path, str):
        return None, f"Wrong path: missing or non-string 'path' in model response for {expected_path}."
    if proposed_path != expected_path:
        return None, f"Wrong path: proposal targets '{proposed_path}' instead of expected '{expected_path}'."
    if not _safe_relative_path(proposed_path):
        return None, f"Wrong path: Unsafe patch path '{proposed_path}' rejected."

    old_text = proposal.get("old_text")
    new_text = proposal.get("new_text")
    if not isinstance(old_text, str) or not old_text:
        return None, f"Missing replacement text: 'old_text' is missing or empty for {expected_path}."
    if not isinstance(new_text, str) or not new_text:
        return None, f"Missing replacement text: 'new_text' is missing or empty for {expected_path}."
    if old_text == new_text:
        return None, f"Unchanged patch: 'new_text' is identical to 'old_text' for {expected_path}."

    occurrences = source.count(old_text)
    if occurrences == 0:
        return None, (
            f"Source context mismatch: old_text was not found in {expected_path}. "
            "Ensure exact original whitespace and line breaks."
        )
    if occurrences > 1:
        return None, (
            f"Non-unique match: old_text matched {occurrences} times in {expected_path}. "
            "Include more surrounding context lines to make it unique."
        )

    replaced = source.replace(old_text, new_text, 1)
    if replaced == source:
        return None, f"Unchanged patch: applying patch produces no source change in {expected_path}."

    validation_error = validate_patched_python(expected_path, source, replaced)
    if validation_error:
        return None, validation_error

    reason = str(proposal.get("reason", "Security remediation proposal"))[:1000]
    return {
        "path": expected_path,
        "old_text": old_text,
        "new_text": new_text,
        "reason": reason,
    }, None
