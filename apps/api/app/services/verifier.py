import ast
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

from app.config import settings
from app.services.analyzer import detect_sql_injection
from app.services.sandbox import SandboxError

SQLI_PAYLOAD_PATTERNS = [
    r"['\"]\s*or\s+['\"\d\w]",
    r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
    r"['\"]\s*or\s+true\b",
    r"['\"]\s*or\s+false\b",
    r"['\"]\s*and\s+['\"\d\w]",
    r"\bunion\s+(?:all\s+)?select\b",
    r"['\"].*--",
    r"--\s*$",
    r"['\"]\s*;",
    r";\s*(?:drop|select|insert|update|delete)\b",
    r"/\*.*\*/",
    r"['\"]\s*#",
]

SECURITY_KEYWORDS = {
    "payload", "injection", "sqli", "exploit", "vulnerab",
    "parameteriz", "query", "unintended", "leak", "bypass",
    "rows", "result", "record", "user", "data", "count",
    "cwe", "security", "blocked", "database", "db", "fetch",
}

BUILTIN_FUNCS = {
    "len", "str", "int", "float", "bool", "list", "dict", "set", "tuple",
    "range", "type", "isinstance", "print", "repr", "iter", "next",
    "min", "max", "sum", "any", "all", "enumerate", "zip", "filter", "map",
}


@dataclass
class VerificationCheck:
    name: str
    status: Literal["passed", "failed", "unverified", "error", "skipped", "unavailable", "not_run"]
    passed: bool
    message: str
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TestClassification:
    outcome: Literal["passed", "assertion_failure", "setup_error", "no_tests_ran", "timeout", "sandbox_error"]
    is_assertion_failure: bool
    is_passed: bool
    message: str
    details: dict[str, Any]


@dataclass
class VerificationGateResult:
    status: Literal["verified", "unverified", "failed", "error"]
    eligible_for_pr: bool
    message: str
    sandbox_provider: str
    static_recheck: VerificationCheck
    security_exploit: VerificationCheck
    regression_tests: VerificationCheck
    tests: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "eligible_for_pr": self.eligible_for_pr,
            "message": self.message,
            "sandbox_provider": self.sandbox_provider,
            "static_recheck": self.static_recheck.as_dict(),
            "security_exploit": self.security_exploit.as_dict(),
            "regression_tests": self.regression_tests.as_dict(),
            "static_recheck_passed": self.static_recheck.passed,
            "security_exploit_passed": self.security_exploit.passed,
            "regression_tests_passed": self.regression_tests.passed,
            "tests": self.tests,
            "before": self.before,
            "after": self.after,
            "details": self.details or {},
        }


def run_static_recheck(
    original_findings: list[dict[str, Any]],
    patched_files: dict[str, str],
    max_findings: int = 10,
) -> VerificationCheck:
    """Re-run the static heuristic on patched files to ensure target findings are gone."""
    remaining_findings = detect_sql_injection(patched_files, max_findings=max_findings)
    original_paths = {item["path"] for item in original_findings}
    remaining_for_targets = [item for item in remaining_findings if item["path"] in original_paths]

    if remaining_for_targets:
        return VerificationCheck(
            name="static_recheck",
            status="failed",
            passed=False,
            message=f"Static recheck failed: {len(remaining_for_targets)} potential vulnerability pattern(s) remain on patched paths.",
            details={"remaining_findings": remaining_for_targets},
        )

    return VerificationCheck(
        name="static_recheck",
        status="passed",
        passed=True,
        message="Static recheck passed: no SQL injection patterns detected on patched files.",
        details={"remaining_findings": []},
    )


def is_test_file(path: str) -> bool:
    """Check if a repository path looks like a Python test file."""
    parts = path.split("/")
    filename = parts[-1]
    if not filename.endswith(".py"):
        return False
    return (
        filename.startswith("test_")
        or filename.endswith("_test.py")
        or any(part in {"tests", "test"} for part in parts[:-1])
    )


def find_existing_security_test(
    files: dict[str, str],
    findings: list[dict[str, Any]],
) -> str | None:
    """Identify if any existing test in the repository specifically targets the reported vulnerability."""
    security_keywords = {
        "sqli", "sql_injection", "injection", "vulnerable", "exploit",
        "parameterized", "payload", "cwe-89", "cwe_89",
    }
    target_stems = {finding["path"].replace(".py", "").split("/")[-1] for finding in findings}

    for path, content in files.items():
        if not is_test_file(path):
            continue
        lower_content = content.lower()
        has_security_keyword = any(kw in lower_content for kw in security_keywords)
        targets_file = any(stem in lower_content for stem in target_stems)

        if has_security_keyword and targets_file:
            return path

    return None


def tests_ran(result: dict[str, Any]) -> bool:
    """Verify that test output reports at least one executed test."""
    combined = f"{result.get('stdout', '')}\n{result.get('stderr', '')}"
    match = re.search(r"Ran\s+(\d+)\s+tests?", combined)
    if match:
        return int(match.group(1)) > 0
    return bool(
        re.search(r"\b\d+\s+passed\b", combined, re.I)
        or re.search(r"\b\d+\s+failed\b", combined, re.I)
    )


def is_sqli_payload_str(s: str) -> bool:
    """Check if a string matches SQL injection payload heuristics."""
    if not isinstance(s, str):
        return False
    s_lower = s.strip().lower()
    return (
        "' or " in s_lower
        or '" or ' in s_lower
        or "' and " in s_lower
        or '" and ' in s_lower
        or "1=1" in s_lower
        or "'1'='1'" in s_lower
        or "union select" in s_lower
        or "union all select" in s_lower
        or "--" in s_lower
        or "/*" in s_lower
        or any(re.search(pat, s_lower) for pat in SQLI_PAYLOAD_PATTERNS)
    )


def has_relevant_sqli_payload(tree: ast.AST, content: str) -> bool:
    """Check if the test code contains a recognized SQL injection payload."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if is_sqli_payload_str(node.value):
                return True

    content_lower = content.lower()
    return any(
        kw in content_lower
        for kw in ["' or 1=1", '" or 1=1', "' or '1'='1", "union select", "' or true", "admin' --", "' or ''='"]
    )


def check_trivial_assertions(tree: ast.AST) -> tuple[bool, str]:
    """Check if test relies on trivial assertions like assertTrue(False) or assertEqual(1, 2)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr == "assertTrue" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and arg.value is False:
                    return True, "trivial assertion assertTrue(False)"
            elif attr == "assertFalse" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and arg.value is True:
                    return True, "trivial assertion assertFalse(True)"
            elif attr == "assertEqual" and len(node.args) >= 2:
                a1, a2 = node.args[0], node.args[1]
                if isinstance(a1, ast.Constant) and isinstance(a2, ast.Constant) and a1.value != a2.value:
                    return True, f"trivial assertion assertEqual({a1.value!r}, {a2.value!r})"
            elif attr == "assertNotEqual" and len(node.args) >= 2:
                a1, a2 = node.args[0], node.args[1]
                if isinstance(a1, ast.Constant) and isinstance(a2, ast.Constant) and a1.value == a2.value:
                    return True, f"trivial assertion assertNotEqual({a1.value!r}, {a2.value!r})"
        elif isinstance(node, ast.Assert):
            if isinstance(node.test, ast.Constant) and node.test.value is False:
                return True, "trivial assertion assert False"
            if isinstance(node.test, ast.Compare):
                left = node.test.left
                comparators = node.test.comparators
                if (
                    isinstance(left, ast.Constant)
                    and len(comparators) == 1
                    and isinstance(comparators[0], ast.Constant)
                    and left.value != comparators[0].value
                ):
                    return True, f"trivial assertion comparing constants ({left.value!r} vs {comparators[0].value!r})"
    return False, ""


def has_meaningful_assertions(tree: ast.AST) -> bool:
    """Ensure the test contains at least one non-trivial assertion."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            if not (isinstance(node.test, ast.Constant) and node.test.value is False):
                return True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr.startswith("assert"):
                if attr in {"assertTrue", "assertFalse"} and node.args:
                    if not isinstance(node.args[0], ast.Constant):
                        return True
                elif attr in {"assertEqual", "assertNotEqual", "assertIn", "assertNotIn"}:
                    if len(node.args) >= 2:
                        if not (isinstance(node.args[0], ast.Constant) and isinstance(node.args[1], ast.Constant)):
                            return True
                elif attr == "assertRaises":
                    return True
                else:
                    return True
        elif isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Attribute):
                    if "assert" in item.context_expr.func.attr.lower():
                        return True
    return False


def exercises_target_code(
    tree: ast.AST,
    content: str,
    target_path: str | None = None,
    finding: dict[str, Any] | None = None,
) -> bool:
    """Verify that the exploit test imports or calls into the target code."""
    candidate_names: set[str] = set()
    path_str = target_path or (finding.get("path") if finding else "") or ""
    if path_str:
        clean_path = path_str.replace("\\", "/")
        if clean_path.endswith(".py"):
            clean_path = clean_path[:-3]
        parts = [p for p in clean_path.split("/") if p]
        if parts:
            candidate_names.add(parts[-1].lower())
            candidate_names.add(".".join(parts).lower())

    if finding:
        evidence = str(finding.get("evidence", ""))
        fn_match = re.search(r"def\s+([a-zA-Z_]\w*)", evidence)
        if fn_match:
            candidate_names.add(fn_match.group(1).lower())

    if not candidate_names:
        return True

    # Check AST imports and references
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                mod_parts = name.name.lower().split(".")
                if any(c in mod_parts for c in candidate_names):
                    return True
        elif isinstance(node, ast.ImportFrom):
            mod_parts = (node.module or "").lower().split(".")
            if any(c in mod_parts for c in candidate_names):
                return True
            for name in node.names:
                if name.name.lower() in candidate_names:
                    return True
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id.lower() in candidate_names:
                return True
            elif isinstance(node.func, ast.Attribute) and node.func.attr.lower() in candidate_names:
                return True
        elif isinstance(node, ast.Name):
            if node.id.lower() in candidate_names:
                return True

    # Fallback with exact word boundary
    content_lower = content.lower()
    return any(bool(re.search(r"\b" + re.escape(c) + r"\b", content_lower)) for c in candidate_names)


def extract_target_context(
    tree: ast.AST,
    target_path: str | None = None,
    finding: dict[str, Any] | None = None,
) -> tuple[set[str], set[str]]:
    """Extract candidate target modules and target function symbols.
    Returns (target_modules, target_symbols).
    """
    target_modules: set[str] = set()
    target_symbols: set[str] = set()

    path_str = target_path or (finding.get("path") if finding else "") or ""
    module_stems: set[str] = set()
    if path_str:
        clean_path = path_str.replace("\\", "/")
        if clean_path.endswith(".py"):
            clean_path = clean_path[:-3]
        parts = [p.lower() for p in clean_path.split("/") if p]
        if parts:
            module_stems.add(parts[-1])
            module_stems.add(".".join(parts))

    if finding:
        evidence = str(finding.get("evidence", ""))
        fn_match = re.search(r"def\s+([a-zA-Z_]\w*)", evidence)
        if fn_match:
            target_symbols.add(fn_match.group(1).lower())

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name.lower()
                mod_parts = mod_name.split(".")
                if any(stem in mod_parts for stem in module_stems):
                    target_modules.add((alias.asname or alias.name).lower())
        elif isinstance(node, ast.ImportFrom):
            mod_name = (node.module or "").lower()
            mod_parts = mod_name.split(".")
            is_target_mod = any(stem in mod_parts for stem in module_stems)
            if is_target_mod or (
                not module_stems
                and node.module not in {
                    "unittest", "pytest", "sys", "os", "re", "json", "sqlite3", "typing", "dataclasses",
                }
            ):
                for alias in node.names:
                    target_symbols.add((alias.asname or alias.name).lower())

    target_modules.update(module_stems)
    return target_modules, target_symbols


def check_method_security_dataflow(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    target_modules: set[str],
    target_symbols: set[str],
) -> tuple[bool, str]:
    """Verify that within a single test method:
    1. SQL injection payload reaches the target code invocation.
    2. No payload variables are left unused.
    3. The security assertion evaluates behavior caused by that invocation (not unrelated function results).
    """
    def expr_has_sqli(expr: ast.AST) -> bool:
        for node in ast.walk(expr):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if is_sqli_payload_str(node.value):
                    return True
        return False

    def expr_uses_vars(expr: ast.AST, var_set: set[str]) -> set[str]:
        return {node.id for node in ast.walk(expr) if isinstance(node, ast.Name) and node.id in var_set}

    # 1. Collect payload variables and payload-carrying expressions
    payload_vars: set[str] = set()
    payload_carrying_vars: set[str] = set()
    var_deps: dict[str, set[str]] = {}

    all_assigns: list[tuple[list[str], ast.AST]] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if names and node.value:
                all_assigns.append((names, node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value:
                all_assigns.append(([node.target.id], node.value))

    for names, val in all_assigns:
        if expr_has_sqli(val):
            for name in names:
                payload_vars.add(name)
                payload_carrying_vars.add(name)
                var_deps[name] = {name}
        elif any(name.lower() in {"payload", "sqli_payload", "attack_payload", "exploit_payload"} for name in names):
            for name in names:
                payload_vars.add(name)
                payload_carrying_vars.add(name)
                var_deps[name] = {name}

    # Propagate payload-carrying variables (e.g. q = payload, params = (payload,))
    for _ in range(3):
        for names, val in all_assigns:
            used = expr_uses_vars(val, payload_carrying_vars)
            if used:
                for name in names:
                    payload_carrying_vars.add(name)
                    var_deps.setdefault(name, set()).update(used)
                    for u in used:
                        var_deps.setdefault(name, set()).update(var_deps.get(u, set()))

    # 2. Identify target call nodes
    def is_target_call(call: ast.Call) -> bool:
        if isinstance(call.func, ast.Name):
            name_lower = call.func.id.lower()
            if target_symbols:
                return name_lower in target_symbols
            return name_lower not in BUILTIN_FUNCS and not name_lower.startswith("assert")
        elif isinstance(call.func, ast.Attribute):
            attr_lower = call.func.attr.lower()
            if target_symbols and attr_lower in target_symbols:
                return True
            if isinstance(call.func.value, ast.Name):
                val_id = call.func.value.id.lower()
                if target_modules:
                    return val_id in target_modules
                return val_id not in {"self", "unittest", "pytest"}
            if isinstance(call.func.value, ast.Attribute) and target_modules:
                return call.func.value.attr.lower() in target_modules
        return False

    used_payload_vars: set[str] = set()
    target_calls_with_payload: list[ast.Call] = []

    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and is_target_call(node):
            all_args = list(node.args) + [kw.value for kw in node.keywords]
            received = False
            for arg in all_args:
                if expr_has_sqli(arg):
                    received = True
                used = expr_uses_vars(arg, payload_carrying_vars)
                if used:
                    received = True
                    for u in used:
                        used_payload_vars.update(var_deps.get(u, {u}))
            if received:
                target_calls_with_payload.append(node)

    # 3. Check for unused payload variables
    unused_payloads = payload_vars - used_payload_vars
    if unused_payloads:
        return (
            False,
            f"Unused payload variable(s) {sorted(unused_payloads)} in method '{fn.name}': payload is defined but does not reach target code invocation.",
        )

    # 4. Must invoke target code with payload
    if not target_calls_with_payload:
        return False, f"Method '{fn.name}' does not invoke target code with an SQL injection payload."

    # 5. Track result variables from target calls
    target_result_vars: set[str] = set()
    unrelated_call_result_vars: set[str] = set()

    for names, val in all_assigns:
        has_target_call = False
        for node in ast.walk(val):
            if node in target_calls_with_payload:
                has_target_call = True
                break
        if has_target_call:
            for name in names:
                target_result_vars.add(name)
        elif any(
            isinstance(node, ast.Call)
            and not (isinstance(node.func, ast.Name) and node.func.id in BUILTIN_FUNCS)
            for node in ast.walk(val)
        ):
            for name in names:
                unrelated_call_result_vars.add(name)
        else:
            if expr_uses_vars(val, target_result_vars):
                for name in names:
                    target_result_vars.add(name)
            else:
                for name in names:
                    unrelated_call_result_vars.add(name)

    # Propagate derived results (e.g. count = len(rows), is_empty = len(rows) == 0)
    for _ in range(3):
        for names, val in all_assigns:
            if expr_uses_vars(val, target_result_vars):
                for name in names:
                    target_result_vars.add(name)

    # 6. Check assertions
    assertions: list[ast.AST] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assert):
            assertions.append(node)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith("assert"):
                assertions.append(node)
        elif isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Attribute):
                    if item.context_expr.func.attr.startswith("assert"):
                        assertions.append(node)

    if not assertions:
        return False, f"Method '{fn.name}' contains no assertions."

    valid_security_assertions: list[ast.AST] = []
    unrelated_assertions: list[tuple[ast.AST, str]] = []

    for assert_node in assertions:
        contains_target = any(node in target_calls_with_payload for node in ast.walk(assert_node))
        if contains_target:
            valid_security_assertions.append(assert_node)
            continue

        used_target = expr_uses_vars(assert_node, target_result_vars)
        if used_target:
            valid_security_assertions.append(assert_node)
            continue

        used_unrelated = expr_uses_vars(assert_node, unrelated_call_result_vars)
        if used_unrelated:
            unrelated_assertions.append((assert_node, ", ".join(sorted(used_unrelated))))
            continue

        unrelated_calls: list[str] = []
        for node in ast.walk(assert_node):
            if isinstance(node, ast.Call):
                fn_name = ""
                if isinstance(node.func, ast.Name):
                    fn_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn_name = node.func.attr
                if fn_name and fn_name not in BUILTIN_FUNCS and not fn_name.startswith("assert") and not is_target_call(node):
                    unrelated_calls.append(f"{fn_name}()")
        if unrelated_calls:
            unrelated_assertions.append((assert_node, ", ".join(unrelated_calls)))
            continue

    if not valid_security_assertions:
        if unrelated_assertions:
            bad_vars = unrelated_assertions[0][1]
            return (
                False,
                f"Security assertion in method '{fn.name}' evaluates unrelated variable/function result ('{bad_vars}') instead of target code invocation result.",
            )
        return (
            False,
            f"Test method '{fn.name}' contains no security assertions evaluating the result of the target code invocation.",
        )

    return True, f"Method '{fn.name}' meaningfully connects target invocation, payload, and assertion."


def validate_security_exploit_test(
    content: str,
    finding: dict[str, Any] | None = None,
    target_path: str | None = None,
) -> tuple[bool, str]:
    """Validate that a security exploit test meaningfully exercises target code with relevant SQLi payload and non-trivial assertions."""
    if not content or not content.strip():
        return False, "Security exploit test content is empty."

    try:
        tree = ast.parse(content)
    except SyntaxError as exc:
        return False, f"Syntax error in exploit test: {exc}"

    # 1. Must define test methods
    test_methods = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")
    ]
    if not test_methods:
        return False, "Exploit test must define at least one test method starting with 'test'."

    # 2. Must exercise target code
    if not exercises_target_code(tree, content, target_path=target_path, finding=finding):
        path_name = target_path or (finding.get("path") if finding else "target code")
        return False, f"Exploit test does not import or exercise the target code from '{path_name}'."

    # 3. Must contain relevant SQL injection payload
    if not has_relevant_sqli_payload(tree, content):
        return False, "Exploit test does not contain a recognized SQL injection payload (e.g. \"' OR 1=1 --\")."

    # 4. Must not have trivial assertions
    is_trivial, trivial_msg = check_trivial_assertions(tree)
    if is_trivial:
        return False, f"Exploit test contains trivial assertion ({trivial_msg}) instead of testing security behavior."

    # 5. Must have meaningful assertions
    if not has_meaningful_assertions(tree):
        return False, "Exploit test does not contain any non-trivial assertions verifying security behavior."

    # 6. Must meaningfully connect target invocation, payload argument, and security assertion
    target_modules, target_symbols = extract_target_context(tree, target_path=target_path, finding=finding)

    # First: reject unused payload variables across all test methods
    for fn in test_methods:
        is_ok, msg = check_method_security_dataflow(fn, target_modules, target_symbols)
        if not is_ok and "Unused payload variable" in msg:
            return False, msg

    # Second: at least one test method must meaningfully connect target invocation, payload, and assertion
    valid_methods: list[str] = []
    method_errors: list[str] = []
    for fn in test_methods:
        is_ok, msg = check_method_security_dataflow(fn, target_modules, target_symbols)
        if is_ok:
            valid_methods.append(fn.name)
        else:
            method_errors.append(msg)

    if not valid_methods:
        err = method_errors[0] if method_errors else "No test method meaningfully connects target invocation, payload argument, and security assertion."
        return False, err

    return True, "Exploit test is valid."


def is_security_assertion_failure(
    combined_output: str,
    test_content: str | None = None,
    finding: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """Check if test failure in output is tied to targeted security behavior rather than an arbitrary/unrelated assertion."""
    lines = combined_output.splitlines()
    failing_code_line = ""
    assertion_error_line = ""

    for i, line in enumerate(lines):
        if "AssertionError" in line:
            assertion_error_line = line
            for j in range(i - 1, max(-1, i - 6), -1):
                candidate = lines[j].strip()
                if candidate and not candidate.startswith("File ") and not candidate.startswith("Traceback"):
                    failing_code_line = candidate
                    break
            break

    failing_lower = failing_code_line.lower()
    if (
        "asserttrue(false)" in failing_lower
        or "assertfalse(true)" in failing_lower
        or failing_lower == "assert false"
        or "assertequal(1, 2)" in failing_lower
        or "assertequal(0, 1)" in failing_lower
        or "assertequal(true, false)" in failing_lower
        or "assert 1 == 2" in failing_lower
    ):
        return False, f"Trivial assertion failure: {failing_code_line}"

    # If test_content is provided, inspect variables tested in failing_code_line
    if test_content:
        try:
            tree = ast.parse(test_content)
            target_modules, target_symbols = extract_target_context(tree, None, finding)
            unrelated_vars: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                    for child in ast.walk(node.value):
                        if isinstance(child, ast.Call):
                            call_name = ""
                            if isinstance(child.func, ast.Name):
                                call_name = child.func.id.lower()
                            elif isinstance(child.func, ast.Attribute):
                                call_name = child.func.attr.lower()
                            if (
                                call_name
                                and call_name not in BUILTIN_FUNCS
                                and call_name not in target_symbols
                            ):
                                for name in names:
                                    unrelated_vars.add(name.lower())
                elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
                    for child in ast.walk(node.value):
                        if isinstance(child, ast.Call):
                            call_name = ""
                            if isinstance(child.func, ast.Name):
                                call_name = child.func.id.lower()
                            elif isinstance(child.func, ast.Attribute):
                                call_name = child.func.attr.lower()
                            if (
                                call_name
                                and call_name not in BUILTIN_FUNCS
                                and call_name not in target_symbols
                            ):
                                unrelated_vars.add(node.target.id.lower())

            tested_unrelated = [v for v in unrelated_vars if re.search(r"\b" + re.escape(v) + r"\b", failing_lower)]
            if tested_unrelated:
                return False, f"Assertion failure on line '{failing_code_line}' evaluates result of unrelated function ('{tested_unrelated[0]}')."
        except Exception:
            pass

    keywords = set(SECURITY_KEYWORDS)
    if finding:
        path = str(finding.get("path", "")).replace(".py", "").split("/")[-1]
        if path:
            keywords.add(path.lower())
        evidence = str(finding.get("evidence", ""))
        fn_match = re.search(r"def\s+([a-zA-Z_]\w*)", evidence)
        if fn_match:
            keywords.add(fn_match.group(1).lower())

    err_lower = assertion_error_line.lower()

    # Check if assertion error line or failing code line has security keywords
    has_security_keyword = any(kw in err_lower for kw in keywords) or any(kw in failing_lower for kw in keywords)

    # Check if query result variables are tested in failing code line (e.g. rows, results, users)
    checks_results = bool(re.search(r"(?:len\s*\(\s*\w+\s*\)|rows|result|users|output|response|data|count)", failing_lower))

    if not has_security_keyword and not checks_results:
        return False, f"Assertion failure on line '{failing_code_line}' does not demonstrate targeted security behavior."

    return True, "Security assertion failure verified."


def classify_test_result(
    result: dict[str, Any],
    test_content: str | None = None,
    finding: dict[str, Any] | None = None,
) -> TestClassification:
    """Distinguish assertion failures from setup errors, import errors, timeouts, and sandbox failures."""
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    combined = f"{stdout}\n{stderr}"
    status = str(result.get("status") or "").lower()
    exit_code = result.get("exit_code")

    # 1. Timeout
    if status == "timeout" or "sandbox timeout" in combined.lower() or "timed out" in combined.lower():
        return TestClassification(
            outcome="timeout",
            is_assertion_failure=False,
            is_passed=False,
            message="Security test execution timed out.",
            details={"status": status, "exit_code": exit_code},
        )

    # 2. Sandbox error / unexecuted
    if status in {"error", "unavailable"} or (exit_code is None and status != "passed"):
        return TestClassification(
            outcome="sandbox_error",
            is_assertion_failure=False,
            is_passed=False,
            message=str(result.get("message") or "Sandbox execution failed."),
            details={"status": status, "exit_code": exit_code},
        )

    # 3. Discovery errors / No tests ran
    has_loader_failed_test = bool(re.search(r"\b_FailedTest\b|unittest\.loader\._FailedTest", combined))
    ran_match = re.search(r"Ran\s+(\d+)\s+tests?", combined)
    test_count = int(ran_match.group(1)) if ran_match else None

    if (test_count == 0) or (test_count is None and not tests_ran(result)):
        return TestClassification(
            outcome="no_tests_ran",
            is_assertion_failure=False,
            is_passed=False,
            message="No security tests were executed (discovery found 0 tests).",
            details={"status": status, "exit_code": exit_code, "test_count": 0},
        )

    # 4. Import / Syntax / Discovery errors
    has_import_error = bool(re.search(r"\b(?:ImportError|ModuleNotFoundError)\b", combined))
    has_syntax_error = bool(re.search(r"\b(?:SyntaxError|IndentationError)\b", combined))
    has_pytest_collect_error = bool(re.search(r"\bERROR collecting\b|\bcollected 0 items\b", combined))

    if has_loader_failed_test or has_import_error or has_syntax_error or has_pytest_collect_error:
        error_type = (
            "import error"
            if has_import_error
            else "syntax error"
            if has_syntax_error
            else "test discovery error"
        )
        return TestClassification(
            outcome="setup_error",
            is_assertion_failure=False,
            is_passed=False,
            message=f"Security test encountered a {error_type} during test setup or discovery.",
            details={"status": status, "exit_code": exit_code, "error_type": error_type},
        )

    # 5. Clean pass
    is_passed = (
        status == "passed"
        and exit_code == 0
        and not bool(re.search(r"\bFAILED\b", combined))
        and not bool(re.search(r"\bFAIL:\s+", combined))
        and not bool(re.search(r"\bERROR:\s+", combined))
    )
    if is_passed:
        return TestClassification(
            outcome="passed",
            is_assertion_failure=False,
            is_passed=True,
            message="Security test executed and passed.",
            details={"status": status, "exit_code": exit_code},
        )

    # 6. Check for Assertion Failure vs other runtime errors
    has_assertion_error = "AssertionError" in combined
    has_unittest_failure = bool(re.search(r"FAILED\s*\([^)]*failures=\d+", combined) or re.search(r"\bFAIL:\s+", combined))
    only_unittest_errors = bool(re.search(r"FAILED\s*\(\s*errors=\d+\s*\)", combined))

    if only_unittest_errors and not has_assertion_error:
        return TestClassification(
            outcome="setup_error",
            is_assertion_failure=False,
            is_passed=False,
            message="Security test failed with an unhandled exception rather than an assertion failure.",
            details={"status": status, "exit_code": exit_code},
        )

    if has_assertion_error or has_unittest_failure:
        is_sec, sec_msg = is_security_assertion_failure(combined, test_content=test_content, finding=finding)
        if not is_sec:
            return TestClassification(
                outcome="setup_error",
                is_assertion_failure=False,
                is_passed=False,
                message=f"Security test failed with an assertion unrelated to the targeted vulnerability: {sec_msg}",
                details={"status": status, "exit_code": exit_code, "security_check": False, "reason": sec_msg},
            )

        return TestClassification(
            outcome="assertion_failure",
            is_assertion_failure=True,
            is_passed=False,
            message="Security test failed with an assertion failure reproducing the vulnerability.",
            details={"status": status, "exit_code": exit_code, "security_check": True},
        )

    # Fallback non-zero exit code without confirmed assertion failure
    return TestClassification(
        outcome="setup_error",
        is_assertion_failure=False,
        is_passed=False,
        message="Security test execution failed without a confirmed assertion failure.",
        details={"status": status, "exit_code": exit_code},
    )


def evaluate_verification_gate(
    static_recheck: VerificationCheck,
    security_exploit: VerificationCheck,
    regression_tests: VerificationCheck,
    sandbox_provider: str,
    tests: dict[str, Any] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    details: dict[str, Any] | None = None,
) -> VerificationGateResult:
    """Evaluate whether all required verification evidence checks pass.

    Rules:
    1. If any check has error status -> result is error, eligible_for_pr=False.
    2. If security exploit test is unavailable -> result is unverified, eligible_for_pr=False.
       (Do not treat unrelated passing tests as proof).
    3. If security exploit test is not_run or unverified -> result is unverified, eligible_for_pr=False.
    4. If static recheck failed -> result is failed, eligible_for_pr=False.
    5. If security exploit test failed -> result is failed, eligible_for_pr=False.
    6. If regression tests failed -> result is failed, eligible_for_pr=False.
    7. Only when static recheck passed, security exploit test passed (differential proof succeeded),
       and regression tests passed/skipped -> verified, eligible_for_pr=True.
    """
    if static_recheck.status == "error" or security_exploit.status == "error" or regression_tests.status == "error":
        error_msg = next(
            (c.message for c in (static_recheck, security_exploit, regression_tests) if c.status == "error"),
            "Sandbox execution error occurred.",
        )
        return VerificationGateResult(
            status="error",
            eligible_for_pr=False,
            message=f"Verification error: {error_msg}",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if security_exploit.status == "unavailable":
        return VerificationGateResult(
            status="unverified",
            eligible_for_pr=False,
            message="Remediation is unverified: a targeted security exploit test could not be generated or identified. Passing unrelated tests does not prove the vulnerability is fixed.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if security_exploit.status in {"not_run", "unverified"} or regression_tests.status in {"not_run", "unverified"}:
        unverified_msg = (
            security_exploit.message
            if security_exploit.status in {"not_run", "unverified"}
            else regression_tests.message
        )
        prefix = "" if unverified_msg.startswith("Remediation is unverified") else "Remediation is unverified: "
        return VerificationGateResult(
            status="unverified",
            eligible_for_pr=False,
            message=f"{prefix}{unverified_msg}",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if not static_recheck.passed:
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message="Verification failed: static recheck still detects potential vulnerability patterns in patched code.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if not security_exploit.passed:
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message=f"Verification failed: {security_exploit.message}",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    if not regression_tests.passed and regression_tests.status != "skipped":
        return VerificationGateResult(
            status="failed",
            eligible_for_pr=False,
            message="Verification failed: regression tests broke after applying the proposed patch.",
            sandbox_provider=sandbox_provider,
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            tests=tests,
            before=before,
            after=after,
            details=details,
        )

    # All required checks passed!
    return VerificationGateResult(
        status="verified",
        eligible_for_pr=True,
        message="All verification checks passed: static recheck cleared, differential exploit verification proved mitigation, and regression tests passed without errors.",
        sandbox_provider=sandbox_provider,
        static_recheck=static_recheck,
        security_exploit=security_exploit,
        regression_tests=regression_tests,
        tests=tests,
        before=before,
        after=after,
        details=details,
    )


async def verify_remediation(
    files: dict[str, str],
    patched_files: dict[str, str],
    findings: list[dict[str, Any]],
    sandbox_service: Any,
    nebius_service: Any = None,
    timeout_seconds: int | None = None,
    sandbox_provider: str | None = None,
) -> VerificationGateResult:
    """Orchestrate differential exploit verification, regression testing, and static recheck."""
    provider = (sandbox_provider or getattr(sandbox_service, "provider", None) or settings.sandbox_provider).strip().lower()

    # 1. Static recheck
    static_recheck = run_static_recheck(findings, patched_files, max_findings=settings.max_findings)

    # 2. Identify or generate the targeted security exploit test
    exploit_test_path: str | None = find_existing_security_test(files, findings)
    exploit_test_content: str | None = None
    is_generated_exploit = False

    if not exploit_test_path and nebius_service and getattr(nebius_service, "configured", False) and findings:
        primary_finding = findings[0]
        source = files.get(primary_finding["path"], "")
        generated = await nebius_service.generate_exploit_test(
            path=primary_finding["path"], source=source, finding=primary_finding
        )
        if generated and generated.get("path") and generated.get("content"):
            exploit_test_path = generated["path"]
            exploit_test_content = generated["content"]
            is_generated_exploit = True
    elif exploit_test_path:
        exploit_test_content = files.get(exploit_test_path, "")

    # Check for demo provider or unexecutable sandbox
    if provider == "demo":
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="not_run",
            passed=False,
            message="Security exploit test was not run: SANDBOX_PROVIDER is set to demo.",
            details={"provider": "demo"},
        )
        regression_tests = VerificationCheck(
            name="regression_tests",
            status="not_run",
            passed=False,
            message="Regression tests were not run: SANDBOX_PROVIDER is set to demo.",
            details={"provider": "demo"},
        )
        return evaluate_verification_gate(
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            sandbox_provider=provider,
        )

    # 3. Security exploit test availability and validation check
    if not exploit_test_path:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unavailable",
            passed=False,
            message="Security exploit test could not be generated or identified. Passing unrelated tests cannot verify the vulnerability is fixed.",
            details={},
        )
        existing_tests = [p for p in files.keys() if is_test_file(p)]
        if not existing_tests:
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="skipped",
                passed=True,
                message="No separate regression test suite detected in repository snapshot.",
                details={"test_files": []},
            )
        else:
            try:
                reg_result = await sandbox_service.run_tests(patched_files, timeout_seconds=timeout_seconds)
                reg_ran = tests_ran(reg_result)
                reg_passed = reg_result.get("status") == "passed" and reg_ran
                regression_tests = VerificationCheck(
                    name="regression_tests",
                    status="passed" if reg_passed else "failed",
                    passed=reg_passed,
                    message="Preexisting regression tests passed without errors." if reg_passed else "Regression tests failed after applying patch.",
                    details=reg_result,
                )
            except SandboxError as exc:
                regression_tests = VerificationCheck(
                    name="regression_tests",
                    status="error",
                    passed=False,
                    message=f"Sandbox error while executing regression tests: {exc}",
                    details={"error": str(exc)},
                )
        return evaluate_verification_gate(
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            sandbox_provider=provider,
        )

    # Validate test content to ensure it meaningfully exercises target code with a payload
    if exploit_test_path and exploit_test_content:
        primary_finding = findings[0] if findings else None
        target_path = primary_finding["path"] if primary_finding else None
        is_valid, validation_msg = validate_security_exploit_test(
            exploit_test_content,
            finding=primary_finding,
            target_path=target_path,
        )
        if not is_valid:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="unverified",
                passed=False,
                message=f"Security exploit test was rejected: {validation_msg}",
                details={"reason": validation_msg, "path": exploit_test_path},
            )
            existing_tests = [p for p in files.keys() if is_test_file(p)]
            if not existing_tests:
                regression_tests = VerificationCheck(
                    name="regression_tests",
                    status="skipped",
                    passed=True,
                    message="No separate regression test suite detected in repository snapshot.",
                    details={"test_files": []},
                )
            else:
                try:
                    reg_result = await sandbox_service.run_tests(patched_files, timeout_seconds=timeout_seconds)
                    reg_ran = tests_ran(reg_result)
                    reg_passed = reg_result.get("status") == "passed" and reg_ran
                    regression_tests = VerificationCheck(
                        name="regression_tests",
                        status="passed" if reg_passed else "failed",
                        passed=reg_passed,
                        message="Preexisting regression tests passed without errors." if reg_passed else "Regression tests failed after applying patch.",
                        details=reg_result,
                    )
                except SandboxError as exc:
                    regression_tests = VerificationCheck(
                        name="regression_tests",
                        status="error",
                        passed=False,
                        message=f"Sandbox error while executing regression tests: {exc}",
                        details={"error": str(exc)},
                    )
            return evaluate_verification_gate(
                static_recheck=static_recheck,
                security_exploit=security_exploit,
                regression_tests=regression_tests,
                sandbox_provider=provider,
            )

    # 4. Prepare snapshots for differential verification
    before_files = dict(files)
    after_files = dict(patched_files)
    if is_generated_exploit and exploit_test_content:
        before_files[exploit_test_path] = exploit_test_content
        after_files[exploit_test_path] = exploit_test_content
    elif exploit_test_path in files and exploit_test_path not in patched_files:
        after_files[exploit_test_path] = files[exploit_test_path]

    test_pattern = exploit_test_path.split("/")[-1]
    primary_finding = findings[0] if findings else None

    # Step A: Differential verification on ORIGINAL snapshot (Before patch)
    before_result: dict[str, Any]
    try:
        before_result = await sandbox_service.run_tests(
            before_files,
            timeout_seconds=timeout_seconds,
            test_pattern=test_pattern,
        )
    except SandboxError as exc:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="error",
            passed=False,
            message=f"Sandbox error while executing security exploit test before patch: {exc}",
            details={"error": str(exc), "stage": "before"},
        )
        regression_tests = VerificationCheck(
            name="regression_tests",
            status="skipped",
            passed=False,
            message="Regression tests skipped due to sandbox error.",
            details={},
        )
        return evaluate_verification_gate(
            static_recheck=static_recheck,
            security_exploit=security_exploit,
            regression_tests=regression_tests,
            sandbox_provider=provider,
        )

    before_class = classify_test_result(
        before_result,
        test_content=exploit_test_content,
        finding=primary_finding,
    )
    before_reproduced = before_class.is_assertion_failure

    before_evidence: dict[str, Any] = {
        "status": before_result.get("status"),
        "exit_code": before_result.get("exit_code"),
        "outcome": before_class.outcome,
        "exploit_reproduced": before_reproduced,
        "message": before_class.message,
        "stdout": before_result.get("stdout", ""),
        "stderr": before_result.get("stderr", ""),
    }

    after_result: dict[str, Any] | None = None
    after_evidence: dict[str, Any]
    security_exploit: VerificationCheck

    if before_class.outcome == "sandbox_error":
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="error",
            passed=False,
            message=f"Sandbox error executing security exploit test before patch: {before_class.message}",
            details={"before": before_evidence},
        )
        after_evidence = {
            "status": "not_run",
            "exit_code": None,
            "outcome": "not_run",
            "exploit_blocked": False,
            "message": "Patched test was not run due to sandbox error on original code.",
            "stdout": "",
            "stderr": "",
        }
    elif before_class.is_passed:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unverified",
            passed=False,
            message="Security exploit test unexpectedly passed against original unpatched code. The vulnerability was not reproduced.",
            details={"before": before_evidence},
        )
        after_evidence = {
            "status": "not_run",
            "exit_code": None,
            "outcome": "not_run",
            "exploit_blocked": False,
            "message": "Patched snapshot test was not executed because the vulnerability was not reproduced on the original snapshot.",
            "stdout": "",
            "stderr": "",
        }
    elif not before_reproduced:
        security_exploit = VerificationCheck(
            name="security_exploit_test",
            status="unverified",
            passed=False,
            message=f"Security exploit test did not reproduce vulnerability on original code ({before_class.message}). Setup and discovery errors do not prove vulnerability.",
            details={"before": before_evidence},
        )
        after_evidence = {
            "status": "not_run",
            "exit_code": None,
            "outcome": "not_run",
            "exploit_blocked": False,
            "message": "Patched snapshot test was not executed because the vulnerability was not reproduced on the original snapshot.",
            "stdout": "",
            "stderr": "",
        }
    else:
        # Before run successfully reproduced the vulnerability via targeted assertion failure!
        # Step B: Differential verification on PATCHED snapshot (After patch)
        try:
            after_result = await sandbox_service.run_tests(
                after_files,
                timeout_seconds=timeout_seconds,
                test_pattern=test_pattern,
            )
        except SandboxError as exc:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="error",
                passed=False,
                message=f"Sandbox error while executing security exploit test after patch: {exc}",
                details={"error": str(exc), "stage": "after", "before": before_evidence},
            )
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="skipped",
                passed=False,
                message="Regression tests skipped due to sandbox error.",
                details={},
            )
            return evaluate_verification_gate(
                static_recheck=static_recheck,
                security_exploit=security_exploit,
                regression_tests=regression_tests,
                sandbox_provider=provider,
                before=before_evidence,
            )

        after_class = classify_test_result(
            after_result,
            test_content=exploit_test_content,
            finding=primary_finding,
        )
        after_blocked = after_class.is_passed

        after_evidence = {
            "status": after_result.get("status"),
            "exit_code": after_result.get("exit_code"),
            "outcome": after_class.outcome,
            "exploit_blocked": after_blocked,
            "message": after_class.message,
            "stdout": after_result.get("stdout", ""),
            "stderr": after_result.get("stderr", ""),
        }

        if after_blocked:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="passed",
                passed=True,
                message="Differential exploit verification succeeded: security test reproduced vulnerability before patch (assertion failed) and passed after patch.",
                details={"before": before_evidence, "after": after_evidence},
            )
        else:
            security_exploit = VerificationCheck(
                name="security_exploit_test",
                status="failed",
                passed=False,
                message=f"Security exploit test failed against patched code: {after_class.message}",
                details={"before": before_evidence, "after": after_evidence},
            )

    # 5. Regression tests execution (run existing tests on patched code)
    existing_tests = [p for p in files.keys() if is_test_file(p)]
    pure_regression_tests = [p for p in existing_tests if p != exploit_test_path]

    regression_tests: VerificationCheck
    combined_test_output: dict[str, Any] | None = after_result or before_result

    if not existing_tests or (exploit_test_path and not pure_regression_tests and not is_generated_exploit):
        regression_tests = VerificationCheck(
            name="regression_tests",
            status="skipped",
            passed=True,
            message="No separate regression test suite detected in repository snapshot.",
            details={"test_files": []},
        )
    else:
        try:
            reg_result = await sandbox_service.run_tests(patched_files, timeout_seconds=timeout_seconds)
            if not after_result:
                combined_test_output = reg_result
            reg_ran = tests_ran(reg_result)
            reg_passed = reg_result.get("status") == "passed" and reg_ran
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="passed" if reg_passed else "failed",
                passed=reg_passed,
                message="Preexisting regression tests passed without errors." if reg_passed else "Regression tests failed after applying patch.",
                details=reg_result,
            )
        except SandboxError as exc:
            regression_tests = VerificationCheck(
                name="regression_tests",
                status="error",
                passed=False,
                message=f"Sandbox error while executing regression tests: {exc}",
                details={"error": str(exc)},
            )

    return evaluate_verification_gate(
        static_recheck=static_recheck,
        security_exploit=security_exploit,
        regression_tests=regression_tests,
        sandbox_provider=provider,
        tests=combined_test_output,
        before=before_evidence,
        after=after_evidence,
    )
