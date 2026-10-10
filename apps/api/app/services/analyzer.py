import ast
import hashlib
import re
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


def detect_sql_injection(files: dict[str, str], max_findings: int = 10) -> list[dict[str, Any]]:
    """Conservative heuristic for Python SQL strings passed to execution APIs.

    A match is a potential finding only. It does not prove exploitability.
    """
    findings: list[DetectedFinding] = []
    for path, source in files.items():
        if not path.endswith(".py"):
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
            raise ValueError(f"Unsafe patch path rejected: {path}")
        if not old or not new:
            raise ValueError(f"Patch for {path} must contain non-empty old_text and new_text.")
        if path not in updated:
            raise ValueError(f"Patch path does not exist in repository snapshot: {path}")
        occurrences = updated[path].count(old)
        if occurrences != 1:
            raise ValueError(f"Patch context for {path} must match exactly once; found {occurrences} matches.")
        updated[path] = updated[path].replace(old, new, 1)
    return updated


def _safe_relative_path(path: str) -> bool:
    from pathlib import PurePosixPath
    p = PurePosixPath(path)
    return bool(path) and not p.is_absolute() and ".." not in p.parts and "\\" not in path and "\x00" not in path
