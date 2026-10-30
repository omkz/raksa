from app.services.workflow import reviewable_patch, unsafe_semantic_replacement, unsafe_shell_replacement


def test_untrusted_command_split_is_rejected() -> None:
    candidate = """
args = shlex.split(user_input)
return subprocess.run(args, check=False).returncode
"""
    assert unsafe_shell_replacement(candidate)


def test_other_subprocess_usage_is_not_automatically_approved() -> None:
    candidate = 'return subprocess.run(["/usr/bin/convert", filename], check=False).returncode'
    assert not unsafe_shell_replacement(candidate)


def test_shell_split_without_execution_does_not_trigger_rule() -> None:
    assert not unsafe_shell_replacement('args = shlex.split(user_input)')


def test_basename_only_path_patch_is_rejected() -> None:
    assert unsafe_semantic_replacement(
        "CWE-22", "open(filename)", "open(os.path.basename(filename))"
    )


def test_disabling_eval_unconditionally_is_rejected() -> None:
    assert unsafe_semantic_replacement(
        "CWE-94", "return eval(expression)", "throw new Error('disabled');"
    )


def test_review_pr_allowlist_is_narrow() -> None:
    assert reviewable_patch({
        "cwe": "CWE-89",
        "old_text": "connection.execute(query)",
        "new_text": "connection.execute(query, (name,))  # ?",
    })
    assert reviewable_patch({
        "cwe": "CWE-79",
        "old_text": "container.innerHTML = message",
        "new_text": "container.textContent = message",
    })
    assert not reviewable_patch({
        "cwe": "CWE-22",
        "old_text": "open(filename)",
        "new_text": "open(os.path.basename(filename))",
    })
    assert not reviewable_patch({
        "cwe": "CWE-94",
        "old_text": "return eval(expression)",
        "new_text": "throw new Error('disabled')",
    })
