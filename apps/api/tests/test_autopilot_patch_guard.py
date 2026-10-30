from app.services.workflow import unsafe_shell_replacement


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
