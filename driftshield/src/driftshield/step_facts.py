"""Fixed list step facts for shell steps.

A shell step is the one place an agent run can do real damage, and the
redactor replaces every tool input with a placeholder, so afterwards ``ls``
and ``git push`` look the same. This module computes four facts from the raw
command *before* redaction and sends only values from closed lists:

``command_kind``
    ``read_only``, ``test``, ``build``, ``git_push``, ``merge``, ``deploy``,
    ``delete``, ``outside_write``, ``unknown``.
``target_kind``
    ``own_checkout``, ``main_branch``, ``outside_service``, ``unknown``.
``exit_status``
    ``success``, ``failure``, ``unknown``.
``checked_before``
    ``True`` when an earlier shell step in the same run was ``read_only``,
    ``test`` or ``build``; ``False`` otherwise.

Nothing else leaves: no command text, path, argument, prompt or code, and no
hash or fingerprint of them. Every value is checked against its list by
:func:`sanitise_step_facts` on the way out, so a bug in a classifier can only
ever produce ``unknown``, never free text.

The command is read locally to decide the kind. Anything that does not match a
known shape, including anything this module cannot parse, is ``unknown``.
There is deliberately no setting that switches this off or lowers it.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
import json
import posixpath
import re
import shlex
from typing import Any

STEP_FACTS_KEY = "step_facts"

COMMAND_KINDS: tuple[str, ...] = (
    "read_only",
    "test",
    "build",
    "git_push",
    "merge",
    "deploy",
    "delete",
    "outside_write",
    "unknown",
)
TARGET_KINDS: tuple[str, ...] = ("own_checkout", "main_branch", "outside_service", "unknown")
EXIT_STATUSES: tuple[str, ...] = ("success", "failure", "unknown")

_CHECK_KINDS = frozenset({"read_only", "test", "build"})
# Most serious first. A compound command takes the most serious kind in it.
_RISK_ORDER: tuple[str, ...] = ("deploy", "merge", "git_push", "delete", "outside_write")
_SAFE_ORDER: tuple[str, ...] = ("build", "test", "read_only")

# Tool names (lower case) that run a shell command, across the supported
# agent transcripts: Claude Code Bash, OpenClaw exec and bash, Codex.
SHELL_TOOL_NAMES = frozenset(
    {"bash", "exec", "shell", "shell_command", "exec_command", "local_shell"}
)

_MAX_COMMAND_CHARS = 16_384
_MAIN_BRANCHES = frozenset({"main", "master", "trunk"})

_Result = tuple[str, str]  # (command_kind, target_kind)
_NEUTRAL: _Result = ("neutral", "own_checkout")
_UNKNOWN: _Result = ("unknown", "unknown")


def unknown_facts(*, checked_before: bool = False) -> dict[str, Any]:
    return {
        "command_kind": "unknown",
        "target_kind": "unknown",
        "exit_status": "unknown",
        "checked_before": checked_before,
    }


def sanitise_step_facts(value: object) -> dict[str, Any] | None:
    """Rebuild ``value`` from the fixed lists, or ``None`` when it is not facts.

    Only the four known keys are read. Each value must be an exact member of
    its list, otherwise it becomes ``unknown`` (``False`` for the flag). No
    other key and no free text can survive.
    """
    if not isinstance(value, Mapping):
        return None
    kind = value.get("command_kind")
    target = value.get("target_kind")
    status = value.get("exit_status")
    return {
        "command_kind": kind if isinstance(kind, str) and kind in COMMAND_KINDS else "unknown",
        "target_kind": target if isinstance(target, str) and target in TARGET_KINDS else "unknown",
        "exit_status": status if isinstance(status, str) and status in EXIT_STATUSES else "unknown",
        "checked_before": value.get("checked_before") is True,
    }


# --------------------------------------------------------------------------- #
# Command classification (command text in, two enum values out)
# --------------------------------------------------------------------------- #

_OPERATORS = frozenset({"&&", "||", ";", ";;", "|", "|&", "&", "<(", ">("})
# shlex glues a run of punctuation into one token (``;(`` or ``&&(``), so a
# token made only of these is cut back into single operators.
_PUNCTUATION_RUN = re.compile(r"[();<>|&]{2,}")
_PUNCTUATION_PIECES = re.compile(r"&&|\|\||\|&|;;|<<<|<<-|<<|&>>|&>|>>|>&|<&|>\||<\(|>\(|[;&|<>()]")
# Words that mean a script, target or command rewrites files.
_WRITE_WORDS = frozenset({"fix", "format", "fmt", "write", "autofix"})
_WRITE_FLAGS = frozenset(
    {
        "--fix",
        "--fix-only",
        "--unsafe-fixes",
        "--write",
        "-w",
        "-u",
        "--update-snapshot",
        "--update-snapshots",
        "--updateSnapshot",
        "--snapshot-update",
    }
)
_FIND_WRITE_FLAGS = (
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-fprint",
    "-fprintf",
    "-fprint0",
    "-fls",
)
_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>"})
_HEREDOC = frozenset({"<<", "<<-", "<<<"})
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = frozenset({"sudo", "time", "nohup", "env", "command", "nice", "builtin", "stdbuf"})
_NEUTRAL_PROGRAMS = frozenset(
    {
        "cd",
        "pushd",
        "popd",
        "export",
        "set",
        "unset",
        "alias",
        "sleep",
        "true",
        "false",
        ":",
        "clear",
        "umask",
        "wait",
        "hash",
        "ulimit",
        "shopt",
        "trap",
        "local",
        "declare",
        "readonly",
    }
)
_READ_ONLY_PROGRAMS = frozenset(
    {
        "ls",
        "cat",
        "head",
        "tail",
        "wc",
        "pwd",
        "echo",
        "printf",
        "date",
        "whoami",
        "which",
        "type",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "ag",
        "sort",
        "uniq",
        "diff",
        "cmp",
        "stat",
        "file",
        "tree",
        "du",
        "df",
        "printenv",
        "jq",
        "yq",
        "basename",
        "dirname",
        "realpath",
        "readlink",
        "uname",
        "id",
        "ps",
        "test",
        "[",
        "nl",
        "cut",
        "tr",
        "column",
        "md5sum",
        "shasum",
        "sha256sum",
        "hostname",
        "uptime",
        "free",
        "lsof",
        "nproc",
        "fd",
        "bat",
        "exa",
        "eza",
        "lscpu",
        "pgrep",
    }
)
_OPAQUE_PROGRAMS = frozenset(
    {
        "bash",
        "sh",
        "zsh",
        "dash",
        "fish",
        "eval",
        "xargs",
        "python",
        "python3",
        "node",
        "perl",
        "ruby",
        "awk",
        "gawk",
        "php",
        "deno",
        "tee",
        "script",
    }
)
_TEST_PROGRAMS = frozenset(
    {
        "pytest",
        "py.test",
        "tox",
        "nox",
        "jest",
        "vitest",
        "mocha",
        "ruff",
        "mypy",
        "pyright",
        "flake8",
        "pylint",
        "eslint",
        "bandit",
        "rspec",
        "phpunit",
        "shellcheck",
        "tflint",
    }
)
_BUILD_PROGRAMS = frozenset(
    {
        "cmake",
        "webpack",
        "rollup",
        "esbuild",
        "tsup",
        "gcc",
        "g++",
        "clang",
        "rustc",
        "javac",
        "ninja",
        "bazel",
        "msbuild",
    }
)
_CHECK_OR_WRITE_FORMATTERS = frozenset({"black", "prettier", "isort", "gofmt"})
_RUNNERS_WITH_RUN = frozenset({"uv", "poetry", "pipenv", "rye", "pdm", "hatch"})
_PACKAGE_MANAGERS = frozenset({"npm", "yarn", "pnpm", "bun"})
_AWS_READ_PREFIXES = ("describe", "list", "get", "head", "batch-get", "lookup", "search")
_AWS_DELETE_PREFIXES = ("delete", "terminate", "remove", "deregister", "destroy", "purge")
_AWS_DEPLOY_OPS = frozenset(
    {"deploy", "update-function-code", "update-service", "create-deployment"}
)
_AWS_WRITE_PREFIXES = (
    "put",
    "create",
    "update",
    "invoke",
    "send",
    "publish",
    "start",
    "stop",
    "attach",
    "detach",
    "tag",
    "untag",
    "run",
    "modify",
    "register",
    "enable",
    "disable",
    "associate",
    "import",
    "export",
    "reboot",
    "set",
    "add",
    "change",
    "copy",
    "restore",
    "reset",
    "revoke",
    "authorize",
)
_GH_READ_ACTIONS = frozenset({"view", "list", "diff", "checks", "status", "watch", "search"})
_GH_WRITE_ACTIONS = frozenset(
    {
        "create",
        "comment",
        "edit",
        "review",
        "close",
        "reopen",
        "ready",
        "lock",
        "unlock",
        "update-branch",
        "transfer",
        "pin",
        "unpin",
        "rerun",
        "cancel",
        "run",
        "enable",
        "disable",
        "set",
        "fork",
        "archive",
        "unarchive",
        "rename",
        "add",
        "develop",
    }
)
_HTTP_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_HTTPIE_PROGRAMS = frozenset({"http", "https", "xh", "xhs"})
_HTTPIE_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)
_HTTPIE_BODY_FLAGS = frozenset({"--form", "-f", "--json", "-j", "--raw", "--multipart"})
_HTTPIE_VALUE_FLAGS = frozenset(
    {
        "-a",
        "--auth",
        "--auth-type",
        "-A",
        "--session",
        "--session-read-only",
        "--timeout",
        "--proxy",
        "--verify",
        "--cert",
        "--cert-key",
        "--pretty",
        "-s",
        "--style",
        "--print",
        "-p",
        "--max-redirects",
        "--default-scheme",
        "--max-headers",
        "--ssl",
        "--ciphers",
        "-o",
        "--output",
    }
)
# Options that take a separate value. A value after one of these is never the
# subcommand, so it is dropped before the subcommand is read (``kubectl -n x
# delete pod y`` is a delete, not a command called ``x``).
_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "kubectl": frozenset(
        {
            "-n",
            "--namespace",
            "--context",
            "--cluster",
            "--user",
            "--kubeconfig",
            "-s",
            "--server",
            "--token",
            "--as",
            "--request-timeout",
        }
    ),
    "helm": frozenset(
        {
            "-n",
            "--namespace",
            "--kube-context",
            "--kubeconfig",
            "--kube-as-user",
            "--registry-config",
        }
    ),
    "aws": frozenset(
        {
            "--profile",
            "--region",
            "--output",
            "--endpoint-url",
            "--query",
            "--cli-input-json",
            "--ca-bundle",
            "--color",
            "--cli-read-timeout",
            "--cli-connect-timeout",
        }
    ),
    "gh": frozenset({"-R", "--repo", "--hostname"}),
    "docker": frozenset({"-H", "--host", "--context", "-c", "--config", "-l", "--log-level"}),
    "npm": frozenset({"--prefix", "-C", "--workspace", "-w", "--registry"}),
    "yarn": frozenset({"--cwd", "--registry"}),
    "pnpm": frozenset({"-C", "--dir", "--filter", "-F", "--registry"}),
    "bun": frozenset({"--cwd", "--filter", "--registry"}),
    "make": frozenset({"-C", "--directory", "-f", "--file", "-j", "--jobs", "-I"}),
    "cargo": frozenset({"--manifest-path", "-p", "--package", "--features", "-F", "--target"}),
    "vercel": frozenset({"--scope", "-S", "--token", "-t", "--cwd"}),
}
_VALUE_FLAGS["oc"] = _VALUE_FLAGS["kubectl"]
_VALUE_FLAGS["podman"] = _VALUE_FLAGS["docker"]
_VALUE_FLAGS["gmake"] = _VALUE_FLAGS["make"]
# Flags of ``uv run`` and friends that take a value, skipped before the
# program they run is read.
_RUNNER_VALUE_FLAGS = frozenset(
    {
        "--extra",
        "--with",
        "--with-requirements",
        "--project",
        "--python",
        "-p",
        "--group",
        "--directory",
        "--package",
        "--env-file",
        "--index",
        "--only-group",
        "--no-group",
        "--package-name",
    }
)
_NPX_VALUE_FLAGS = frozenset({"-p", "--package", "--registry", "--cache"})
_NO_FLAGS: frozenset[str] = frozenset()
_CURL_BODY_FLAGS = frozenset(
    {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "--data-ascii",
        "-F",
        "--form",
        "--form-string",
        "-T",
        "--upload-file",
        "--json",
    }
)
_SSH_VALUE_FLAGS = frozenset(
    {"-i", "-p", "-o", "-l", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-E"}
)


def _split_unquoted_newlines(command: str) -> str:
    """Turn newlines outside quotes into ``;`` so shlex sees separate commands."""
    out: list[str] = []
    quote = ""
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            out.append(char)
            continue
        if char == "\\" and quote != "'":
            escaped = True
            out.append(char)
            continue
        if quote:
            if char == quote:
                quote = ""
            out.append(char)
            continue
        if char in "'\"":
            quote = char
            out.append(char)
            continue
        out.append(" ; " if char == "\n" else char)
    return "".join(out)


def _tokenise(command: str) -> list[str] | None:
    try:
        lexer = shlex.shlex(_split_unquoted_newlines(command), posix=True, punctuation_chars=True)
        lexer.whitespace_split = False
        # shlex ends a word at these when punctuation_chars is on; they are plain
        # characters in refs and URLs (HEAD:main, user@host, a+b, 1,2).
        lexer.wordchars += ":@%+,^"
        tokens: list[str] = []
        for token in lexer:
            if _PUNCTUATION_RUN.fullmatch(token):
                tokens.extend(_PUNCTUATION_PIECES.findall(token))
            else:
                tokens.append(token)
        return tokens
    except ValueError:
        return None


def _segments(tokens: list[str]) -> tuple[list[list[str]], bool]:
    """Split into simple commands. The flag is True for a write redirect or heredoc."""
    segments: list[list[str]] = [[]]
    opaque = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _OPERATORS:
            segments.append([])
        elif token in _HEREDOC:
            opaque = True
            index += 1
        elif token in _REDIRECTS or re.fullmatch(r"\d?>>?", token):
            target = tokens[index + 1] if index + 1 < len(tokens) else ""
            if target not in {"/dev/null", "&", "&1", "&2"}:
                opaque = True
            index += 1
        elif token in {">&", "<", "<&", "2>&"}:
            index += 1
        elif token == "(" and index > 0 and tokens[index - 1].endswith("$"):
            segments.append([])  # a command substitution: its words are their own command
        elif token not in {"(", ")", "{", "}", "!"}:
            segments[-1].append(token)
        index += 1
    return [segment for segment in segments if segment], opaque


def _strip_prefixes(tokens: list[str]) -> list[str]:
    tokens = list(tokens)
    while tokens:
        head = tokens[0]
        if _ENV_ASSIGNMENT.match(head):
            tokens.pop(0)
        elif head in _WRAPPERS:
            tokens.pop(0)
        elif head == "timeout":
            tokens.pop(0)
            while tokens and (
                tokens[0].startswith("-") or re.fullmatch(r"[0-9.]+[smhd]?", tokens[0])
            ):
                tokens.pop(0)
        else:
            break
    return tokens


def _drop_value_flags(tokens: list[str], flags: frozenset[str]) -> list[str]:
    """``tokens`` without the options in ``flags`` and the value that follows each."""
    if not flags:
        return tokens
    kept: list[str] = []
    skip = False
    for token in tokens:
        if skip:
            skip = False
        elif token in flags:
            skip = True
        else:
            kept.append(token)
    return kept


def _skip_leading_flags(tokens: list[str], value_flags: frozenset[str]) -> list[str]:
    index = 0
    while index < len(tokens) and tokens[index].startswith("-") and tokens[index] != "--":
        index += 2 if tokens[index] in value_flags else 1
    if index < len(tokens) and tokens[index] == "--":
        index += 1
    return tokens[index:]


def _unwrap_runner(tokens: list[str]) -> list[str]:
    """``uv run pytest`` and ``npx vitest`` are classified as the program they run."""
    for _ in range(4):
        if not tokens:
            return tokens
        head = tokens[0].lower()
        if head in _RUNNERS_WITH_RUN and len(tokens) > 2 and tokens[1] == "run":
            tokens = _strip_prefixes(_skip_leading_flags(tokens[2:], _RUNNER_VALUE_FLAGS))
        elif head in {"npx", "bunx", "pipx"} or (
            head == "pnpm" and tokens[1:2] in (["dlx"], ["exec"])
        ):
            skip = 1 if head != "pnpm" else 2
            tokens = _skip_leading_flags(tokens[skip:], _NPX_VALUE_FLAGS)
        elif head == "bundle" and tokens[1:2] == ["exec"]:
            tokens = tokens[2:]
        elif head in {"python", "python3", "py"} and tokens[1:2] == ["-m"] and len(tokens) > 2:
            module = tokens[2]
            if module == "build":
                tokens = ["uv", "build"]
            elif module == "unittest":
                tokens = ["pytest"]
            elif module in {"venv", "http.server", "json.tool"}:
                return ["python", "-m", module]
            else:
                tokens = [module, *tokens[3:]]
        else:
            return tokens
    return tokens


def _positionals(tokens: list[str]) -> list[str]:
    return [token for token in tokens if not token.startswith("-")]


def _has_flag(tokens: list[str], *flags: str) -> bool:
    return any(token in flags or any(token.startswith(f + "=") for f in flags) for token in tokens)


def _writes_a_file(program: str, rest: list[str], positional: list[str]) -> bool:
    """True for a normally read only program called in a way that writes a file."""
    if program in {"sort", "tree"} and (
        _has_flag(rest, "-o", "--output") or any(t.startswith("-o") and len(t) > 2 for t in rest)
    ):
        return True
    if program == "yq" and (_has_flag(rest, "--inplace") or any(t.startswith("-i") for t in rest)):
        return True
    if program == "uniq" and len(positional) > 1:
        return True  # the second operand is the output file
    if program == "date" and _has_flag(rest, "-s", "--set"):
        return True
    return program == "hostname" and bool(positional)


def _fs_target(paths: list[str]) -> str:
    for path in paths:
        if (
            path.startswith(("/", "~"))
            or "$" in path
            or ".." in posixpath.normpath(path).split("/")
        ):
            return "unknown"
    return "own_checkout"


def _git(rest: list[str]) -> _Result:
    index = 0
    while index < len(rest) and rest[index].startswith("-"):
        index += 2 if rest[index] in {"-C", "-c", "--git-dir", "--work-tree"} else 1
    if index >= len(rest):
        return _UNKNOWN
    sub, args = rest[index], rest[index + 1 :]
    positional = _positionals(args)
    if _has_flag(args, "--output") and sub in {"diff", "log", "show", "blame", "grep"}:
        return _UNKNOWN  # writes the result to a file
    if sub == "push":
        refs = [a for a in positional[1:]] if positional else []
        if _has_flag(args, "--delete", "-d") or any(r.startswith(":") for r in refs):
            return "delete", "outside_service"
        for ref in refs:
            name = ref.rsplit(":", 1)[-1].removeprefix("refs/heads/").lstrip("+")
            if name in _MAIN_BRANCHES:
                return "git_push", "main_branch"
        return "git_push", "outside_service"
    if sub == "merge":
        return "merge", "own_checkout"
    if sub in {
        "status",
        "diff",
        "log",
        "show",
        "rev-parse",
        "ls-files",
        "blame",
        "describe",
        "shortlog",
        "grep",
        "rev-list",
        "cat-file",
        "merge-base",
        "name-rev",
        "diff-tree",
        "for-each-ref",
        "ls-tree",
        "whatchanged",
        "count-objects",
        "verify-commit",
        "check-ignore",
        "show-ref",
    }:
        return "read_only", "own_checkout"
    if sub == "ls-remote":
        return "read_only", "outside_service"
    if sub == "branch":
        if _has_flag(args, "-d", "-D", "--delete"):
            return "delete", "own_checkout"
        if positional and not _has_flag(
            args, "--list", "-l", "--contains", "--merged", "--no-merged"
        ):
            return _UNKNOWN
        if _has_flag(args, "-m", "-M", "-c", "-C", "--move", "--copy", "-u", "--set-upstream-to"):
            return _UNKNOWN
        return "read_only", "own_checkout"
    if sub == "tag":
        if _has_flag(args, "-d", "--delete"):
            return "delete", "own_checkout"
        return (
            ("read_only", "own_checkout")
            if not positional or _has_flag(args, "-l", "--list")
            else _UNKNOWN
        )
    if sub == "remote":
        if positional[:1] in (["add"], ["remove"], ["rm"], ["rename"], ["set-url"], ["prune"]):
            return _UNKNOWN
        return "read_only", "own_checkout"
    if sub == "config":
        return (
            ("read_only", "own_checkout")
            if _has_flag(args, "--get", "--list", "-l", "--get-all")
            else _UNKNOWN
        )
    if sub == "stash":
        if positional[:1] in (["list"], ["show"]):
            return "read_only", "own_checkout"
        if positional[:1] in (["drop"], ["clear"]):
            return "delete", "own_checkout"
        return _UNKNOWN
    if sub == "worktree":
        return ("read_only", "own_checkout") if positional[:1] == ["list"] else _UNKNOWN
    if sub in {"clean", "rm"}:
        return "delete", "own_checkout"
    return _UNKNOWN


def _gh(rest: list[str]) -> _Result:
    words = _positionals(rest)
    if not words:
        return _UNKNOWN
    group = words[0]
    action = words[1] if len(words) > 1 else ""
    if group == "api":
        method = "GET"
        for index, token in enumerate(rest):
            if token in {"-X", "--method"} and index + 1 < len(rest):
                method = rest[index + 1].upper()
            elif token.startswith("-X") and len(token) > 2:
                method = token[2:].upper()
            elif token.startswith("--method="):
                method = token.split("=", 1)[1].upper()
        if method == "DELETE":
            return "delete", "outside_service"
        if method not in _HTTP_READ_METHODS or _has_flag(
            rest, "-f", "-F", "--field", "--raw-field", "--input"
        ):
            return "outside_write", "outside_service"
        return "read_only", "outside_service"
    if group == "search" or (group == "auth" and action == "status"):
        return "read_only", "outside_service"
    if group == "pr" and action == "merge":
        return "merge", "outside_service"
    if group == "release":
        if action == "delete":
            return "delete", "outside_service"
        if action in {"create", "upload", "edit"}:
            return "deploy", "outside_service"
    if action in {"delete", "delete-asset"}:
        return "delete", "outside_service"
    if action in _GH_READ_ACTIONS:
        return "read_only", "outside_service"
    if action in _GH_WRITE_ACTIONS:
        return "outside_write", "outside_service"
    return _UNKNOWN


def _downloads_to_file(program: str, rest: list[str]) -> bool:
    """True when curl or wget saves the response to a file (anything but stdout or null)."""
    sinks = {"-", "/dev/null", "NUL"}
    if program == "wget":
        if _has_flag(rest, "--spider"):
            return False
        for index, token in enumerate(rest):
            if token in {"-O", "--output-document"} and index + 1 < len(rest):
                return rest[index + 1] not in sinks
            if token.startswith("--output-document="):
                return token.split("=", 1)[1] not in sinks
            short = re.fullmatch(r"-[A-Za-z]*O(.+)", token)
            if short:  # value attached to the short flag, as in -qO-
                return short.group(1) not in sinks
            if re.fullmatch(r"-[A-Za-z]+O", token) and index + 1 < len(rest):
                return rest[index + 1] not in sinks
        return True
    for index, token in enumerate(rest):
        value = rest[index + 1] if index + 1 < len(rest) else ""
        if token in {"-o", "--output"} or (re.fullmatch(r"-[A-Za-z]+", token) and token[-1] == "o"):
            if value not in sinks:
                return True
        elif token.startswith("--output="):
            if token.split("=", 1)[1] not in sinks:
                return True
        elif token in {"-O", "--remote-name", "--remote-name-all", "-J"}:
            return True
        elif re.fullmatch(r"-[A-Za-z]+", token) and "O" in token:
            return True
    return False


def _httpie(rest: list[str]) -> _Result:
    """HTTPie and xh: the method is a positional word, request items give a body."""
    flags_dropped = _drop_value_flags(rest, _HTTPIE_VALUE_FLAGS)
    words = _positionals(flags_dropped)
    method = ""
    if words and words[0].upper() in _HTTPIE_METHODS:
        method = words[0].upper()
        words = words[1:]
    items = words[1:]  # the first word left is the URL
    has_body = _has_flag(rest, *_HTTPIE_BODY_FLAGS) or any(
        ("=" in item and "==" not in item) or ":=" in item or "@" in item.split(":", 1)[0]
        for item in items
    )
    if method == "DELETE":
        return "delete", "outside_service"
    if (method and method not in _HTTP_READ_METHODS) or has_body:
        return "outside_write", "outside_service"
    if any(token in {"-d", "--download", "-o", "--output"} for token in rest):
        return _UNKNOWN  # saves the response to a file
    return "read_only", "outside_service"


def _http_client(program: str, rest: list[str]) -> _Result:
    method = "GET"
    for index, token in enumerate(rest):
        if token in {"-X", "--request", "--method"} and index + 1 < len(rest):
            method = rest[index + 1].upper()
        elif token.startswith("-X") and len(token) > 2:
            method = token[2:].upper()
        elif token.startswith(("--request=", "--method=")):
            method = token.split("=", 1)[1].upper()
    body = _has_flag(rest, *_CURL_BODY_FLAGS) or any(
        token.startswith(("-d", "-F", "-T")) and len(token) > 2 and not token.startswith("--")
        for token in rest
    )
    if program == "wget":
        body = _has_flag(rest, "--post-data", "--post-file")
    if method == "DELETE":
        return "delete", "outside_service"
    if method not in _HTTP_READ_METHODS or body:
        return "outside_write", "outside_service"
    if _downloads_to_file(program, rest):
        return _UNKNOWN
    return "read_only", "outside_service"


def _remote_shell(program: str, rest: list[str]) -> _Result:
    positional: list[str] = []
    skip = False
    for token in rest:
        if skip:
            skip = False
            continue
        if token in _SSH_VALUE_FLAGS:
            skip = True
        elif not token.startswith("-"):
            positional.append(token)
    if program == "ssh":
        return ("outside_write", "outside_service") if len(positional) >= 2 else _UNKNOWN
    if any(":" in item.split("/", 1)[0] for item in positional):
        return "outside_write", "outside_service"
    return _UNKNOWN


def _aws(rest: list[str]) -> _Result:
    words = _positionals(rest)
    if len(words) < 2:
        return _UNKNOWN
    service, operation = words[0], words[1]
    if service == "s3":
        if operation in {"ls"}:
            return "read_only", "outside_service"
        if operation in {"rm", "rb"}:
            return "delete", "outside_service"
        if operation in {"cp", "mv", "sync", "mb", "presign"}:
            return "outside_write", "outside_service"
        return _UNKNOWN
    if operation in _AWS_DEPLOY_OPS:
        return "deploy", "outside_service"
    if operation.startswith(_AWS_READ_PREFIXES):
        return "read_only", "outside_service"
    if operation.startswith(_AWS_DELETE_PREFIXES):
        return "delete", "outside_service"
    if operation.startswith(_AWS_WRITE_PREFIXES):
        return "outside_write", "outside_service"
    return _UNKNOWN


def _kubectl(program: str, rest: list[str]) -> _Result:
    words = _positionals(rest)
    sub = words[0] if words else ""
    if program == "helm":
        if sub in {
            "list",
            "ls",
            "status",
            "get",
            "show",
            "search",
            "template",
            "lint",
            "history",
            "version",
            "repo",
        }:
            return "read_only", "outside_service"
        if sub in {"uninstall", "delete"}:
            return "delete", "outside_service"
        if sub in {"install", "upgrade", "rollback"}:
            return "deploy", "outside_service"
        return _UNKNOWN
    if sub in {
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        "version",
        "cluster-info",
        "api-resources",
        "diff",
    }:
        return "read_only", "outside_service"
    if sub == "auth":
        # can-i and whoami only ask; reconcile writes RBAC objects.
        return (
            ("read_only", "outside_service") if words[1:2] in (["can-i"], ["whoami"]) else _UNKNOWN
        )
    if sub == "config":
        return (
            ("read_only", "outside_service")
            if words[1:2] in (["view"], ["get-contexts"], ["current-context"])
            else _UNKNOWN
        )
    if sub == "delete":
        return "delete", "outside_service"
    if sub in {
        "apply",
        "create",
        "patch",
        "replace",
        "scale",
        "rollout",
        "set",
        "edit",
        "autoscale",
        "expose",
        "run",
    }:
        return "deploy", "outside_service"
    return _UNKNOWN


def _package_manager(program: str, rest: list[str]) -> _Result:
    words = _positionals(rest)
    sub = words[0] if words else ""
    if sub == "run" and len(words) > 1:
        if _WRITE_WORDS & set(re.split(r"[:_.\-]", words[1].lower())):
            return _UNKNOWN  # lint:fix, format and the like rewrite files
        script = words[1].split(":", 1)[0]
        sub = {
            "test": "test",
            "tests": "test",
            "lint": "test",
            "typecheck": "test",
            "check": "test",
            "build": "build",
            "compile": "build",
        }.get(script, "")
    if sub in {"test", "t", "tsc"}:
        return "test", "own_checkout"
    if sub in {"build", "pack"}:
        return "build", "own_checkout"
    if sub == "audit" and "fix" in words:
        return _UNKNOWN  # rewrites the lockfile
    if sub in {"publish"}:
        return "deploy", "outside_service"
    if sub in {
        "ls",
        "list",
        "view",
        "info",
        "outdated",
        "audit",
        "explain",
        "why",
        "whoami",
        "ping",
    }:
        return "read_only", "outside_service" if sub in {
            "view",
            "info",
            "audit",
            "outdated",
            "ping",
            "whoami",
        } else "own_checkout"
    return _UNKNOWN


def _make_like(program: str, rest: list[str]) -> _Result:
    words = _positionals(rest)
    target = words[0] if words else ""
    if program == "make" or program == "gmake":
        if _WRITE_WORDS & set(re.split(r"[:_.\-]", target.lower())):
            return _UNKNOWN
        if target in {"test", "tests", "check", "lint", "typecheck", "verify"}:
            return "test", "own_checkout"
        if target in {"deploy", "release", "publish", "push", "apply"}:
            return "deploy", "outside_service"
        if target in {"clean", "distclean"}:
            return "delete", "own_checkout"
        if target in {"", "all", "build", "compile", "dist", "package"}:
            return "build", "own_checkout"
        return _UNKNOWN
    # gradle, mvn, dotnet, cargo, go, tsc and similar.
    if target in {"test", "check", "verify", "vet", "clippy", "lint", "integrationtest"}:
        return "test", "own_checkout"
    if target in {
        "build",
        "package",
        "compile",
        "assemble",
        "install",
        "jar",
        "bootjar",
        "publish",
    }:
        return ("deploy", "outside_service") if target == "publish" else ("build", "own_checkout")
    return _UNKNOWN


def _classify_simple(tokens: list[str]) -> _Result:
    result = _classify_program(tokens)
    if result[0] == "test":
        # A formatter or a fixer rewrites files, so it is not a check.
        unwrapped = _unwrap_runner(_strip_prefixes(tokens))
        if any(
            token in _WRITE_FLAGS or token.startswith(("--fix=", "--write=")) for token in unwrapped
        ):
            return _UNKNOWN
    return result


def _classify_program(tokens: list[str]) -> _Result:
    tokens = _unwrap_runner(_strip_prefixes(tokens))
    if not tokens:
        return _NEUTRAL
    head = tokens[0]
    if head.startswith(("./", "../", "~")) or head == "." and len(tokens) > 1:
        return _UNKNOWN
    program = posixpath.basename(head).lower() if head.startswith("/") else head.lower()
    rest = _drop_value_flags(tokens[1:], _VALUE_FLAGS.get(program, _NO_FLAGS))
    positional = _positionals(rest)

    if program == "source" or program == ".":
        return _NEUTRAL if positional and positional[0].endswith("activate") else _UNKNOWN
    if program in _NEUTRAL_PROGRAMS:
        return _NEUTRAL
    if program in _OPAQUE_PROGRAMS:
        return _UNKNOWN
    if program == "git" or program == "jj":
        return _git(rest if program == "git" else [t for t in rest if t != "git"])
    if program == "gh":
        return _gh(rest)
    if program in _HTTPIE_PROGRAMS:
        return _httpie(rest)
    if program in {"curl", "wget"}:
        return _http_client(program, rest)
    if program in {"ssh", "scp", "rsync", "sftp"}:
        return _remote_shell(program, rest)
    if program == "aws":
        return _aws(rest)
    if program in {"kubectl", "helm", "oc"}:
        return _kubectl(program, rest)
    if program in _PACKAGE_MANAGERS:
        return _package_manager(program, rest)
    if program in {"make", "gmake"}:
        return _make_like("make", rest)
    if program in {
        "go",
        "cargo",
        "mvn",
        "mvnw",
        "gradle",
        "gradlew",
        "dotnet",
        "swift",
        "mix",
        "sbt",
    }:
        if program == "cargo" and positional[:1] == ["publish"]:
            return "deploy", "outside_service"
        if program == "cargo" and positional[:1] == ["fmt"]:
            return ("test", "own_checkout") if _has_flag(rest, "--check") else _UNKNOWN
        return _make_like(program, rest)
    if program in {"tsc", "vite", "next", "nuxt", "astro"}:
        if program == "tsc":
            return ("test" if _has_flag(rest, "--noEmit") else "build"), "own_checkout"
        return ("build", "own_checkout") if positional[:1] == ["build"] else _UNKNOWN
    if program == "ruff" and positional[:1] == ["format"]:
        return ("test", "own_checkout") if _has_flag(rest, "--check", "--diff") else _UNKNOWN
    if program in _TEST_PROGRAMS:
        return "test", "own_checkout"
    if program in {"playwright", "cypress"}:
        return ("test", "own_checkout") if positional[:1] in (["test"], ["run"]) else _UNKNOWN
    if program in _CHECK_OR_WRITE_FORMATTERS:
        return (
            ("test", "own_checkout")
            if _has_flag(rest, "--check", "--diff", "-check", "-l")
            else _UNKNOWN
        )
    if program in _BUILD_PROGRAMS:
        return "build", "own_checkout"
    if program in {"pip", "pip3", "uv"}:
        if program == "uv" and positional[:1] == ["build"]:
            return "build", "own_checkout"
        if program == "uv" and positional[:1] == ["publish"]:
            return "deploy", "outside_service"
        words = positional[1:] if program == "uv" and positional[:1] == ["pip"] else positional
        return (
            ("read_only", "own_checkout")
            if words[:1] in (["list"], ["show"], ["freeze"], ["check"])
            else _UNKNOWN
        )
    if program in {
        "twine",
        "poetry",
        "gem",
        "docker",
        "podman",
        "terraform",
        "tofu",
        "vercel",
        "netlify",
        "fly",
        "flyctl",
        "serverless",
        "sls",
        "cdk",
        "sam",
        "wrangler",
        "firebase",
        "heroku",
    }:
        return _infra_tool(program, positional, rest)
    if program in {"rm", "rmdir", "unlink", "shred", "trash"}:
        return "delete", _fs_target(positional)
    if program == "find":
        if _has_flag(rest, "-delete"):
            return "delete", _fs_target(positional)
        if _has_flag(rest, *_FIND_WRITE_FLAGS):
            return _UNKNOWN
        return "read_only", _fs_target(positional)
    if program == "sed":
        # Only a plain line print. Any other script can write (w) or run (e) things.
        if (
            "-n" in rest
            and positional
            and re.fullmatch(r"[0-9$]+(,[0-9$]+)?p", positional[0])
            and not any(t.startswith(("-i", "--in-place", "-e", "-f")) for t in rest)
        ):
            return "read_only", _fs_target(positional[1:])
        return _UNKNOWN
    if program == "systemctl":
        return (
            ("read_only", "outside_service")
            if positional[:1] in (["status"], ["is-active"], ["list-units"])
            else _UNKNOWN
        )
    if program in _READ_ONLY_PROGRAMS:
        if _writes_a_file(program, rest, positional) or (
            program in {"fd", "rg", "ag"}
            and _has_flag(rest, "-x", "-X", "--exec", "--exec-batch", "--pre")
        ):
            return _UNKNOWN
        return "read_only", _fs_target(positional)
    return _UNKNOWN


def _infra_tool(program: str, positional: list[str], rest: list[str]) -> _Result:
    sub = positional[0] if positional else ""
    if program in {"terraform", "tofu"}:
        if sub == "fmt":
            # fmt rewrites files unless it is only checking.
            return ("read_only", "own_checkout") if _has_flag(rest, "-check") else _UNKNOWN
        if sub == "plan" and _has_flag(rest, "-out"):
            return _UNKNOWN  # writes a plan file
        if sub in {"plan", "show", "validate", "output", "version", "providers", "graph"}:
            return "read_only", "outside_service"
        if sub == "init":
            return "build", "own_checkout"
        if sub == "apply":
            return "deploy", "outside_service"
        if sub == "destroy":
            return "delete", "outside_service"
        if sub == "state" and positional[1:2] in (["list"], ["show"]):
            return "read_only", "outside_service"
        return _UNKNOWN
    if program in {"docker", "podman"}:
        if sub in {"ps", "images", "logs", "inspect", "info", "version", "stats", "top", "history"}:
            return "read_only", "own_checkout"
        if sub == "build" or (sub == "buildx" and positional[1:2] == ["build"]):
            return "build", "own_checkout"
        if sub == "push":
            return "deploy", "outside_service"
        if sub in {"rm", "rmi", "prune", "kill"} or (
            sub in {"system", "volume", "image", "container", "network"}
            and positional[1:2] in (["prune"], ["rm"])
        ):
            return "delete", "own_checkout"
        return _UNKNOWN
    if program == "vercel":
        if sub in {"ls", "list", "inspect", "logs", "whoami", "domains"}:
            return "read_only", "outside_service"
        if (
            sub in {"", "deploy", "promote", "rollback", "redeploy", "--prod"}
            or "/" in sub
            or sub == "."
        ):
            return "deploy", "outside_service"
        if sub == "env":
            second = positional[1:2]
            if second in (["ls"], ["list"]):
                return "read_only", "outside_service"
            if second in (["rm"], ["remove"]):
                return "delete", "outside_service"
            if second in (["add"],):
                return "outside_write", "outside_service"
        return _UNKNOWN
    if program in {"twine"}:
        return ("deploy", "outside_service") if sub == "upload" else _UNKNOWN
    if program in {"poetry"}:
        if sub == "publish":
            return "deploy", "outside_service"
        return ("build", "own_checkout") if sub == "build" else _UNKNOWN
    if program == "gem":
        return ("deploy", "outside_service") if sub == "push" else _UNKNOWN
    if (
        sub in {"deploy", "release", "publish", "up"}
        or program in {"sam", "cdk"}
        and sub == "deploy"
    ):
        return "deploy", "outside_service"
    return _UNKNOWN


def classify_command(command: object) -> tuple[str, str]:
    """``(command_kind, target_kind)`` for a command string, from fixed lists.

    Never raises, never returns anything outside the lists. A command that is
    not text, is too long to read safely, or does not match a known shape is
    ``("unknown", "unknown")``. A command that substitutes other commands
    (``$(...)`` or backticks) or writes through a redirect cannot be called
    ``read_only``, ``test`` or ``build``.
    """
    try:
        return _classify_command(command)
    except Exception:  # noqa: BLE001 - a hostile command must degrade to unknown, never raise
        return "unknown", "unknown"


def _has_shell_operators(command: str) -> bool:
    """True when ``command`` is more than one plain simple command.

    Looks for ``; & | ( ) < >`` and newlines outside quotes, and for ``$(`` and
    backticks anywhere except inside single quotes. Quoted text is skipped
    because it is an argument, not shell syntax.
    """
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote == "'":
            if char == "'":
                quote = ""
            continue
        if char == "`" or (char == "$" and command[index + 1 : index + 2] == "("):
            return True
        if quote == "" and char == "#" and (index == 0 or command[index - 1].isspace()):
            return True  # a comment hides the rest of the line from the reader
        if quote == '"':
            if char == '"':
                quote = ""
            continue
        if char in "'\"":
            quote = char
        elif char in ";&|()<>\n\r":
            return True
    return bool(quote)  # an unterminated quote is not a command we can read


_MAX_SUBSTITUTION_DEPTH = 4
_MAX_SUBSTITUTION_BODIES = 64
_MAX_SUBSTITUTION_WORK = 100_000  # characters read across all levels
_HEREDOC_OPERATOR = re.compile(r"<<(?!<)(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\(\w+)|(\w+))")


def _heredoc_spans(text: str) -> list[tuple[int, int, bool]]:
    """``(start, end, quoted)`` of every here document body, in order.

    A body is data, not commands, so it is cut out before the command is split
    into parts. Only a quoted delimiter (``<<'EOF'``) also stops substitutions
    from running inside the body; an unquoted body still expands them.
    """
    spans: list[tuple[int, int, bool]] = []
    position = 0
    while True:
        match = _HEREDOC_OPERATOR.search(text, position)
        if match is None:
            return spans
        dash, single, double, escaped, bare = match.groups()
        delimiter = next(d for d in (single, double, escaped, bare) if d is not None)
        quoted = bare is None
        line_end = text.find("\n", match.end())
        if line_end == -1:
            return spans
        terminator = re.compile(
            r"^" + (r"[ \t]*" if dash else "") + re.escape(delimiter) + r"[ \t]*$", re.M
        ).search(text, line_end + 1)
        end = terminator.end() if terminator else len(text)
        spans.append((line_end + 1, end, quoted))
        position = end


def _without_heredoc_bodies(text: str, spans: list[tuple[int, int, bool]]) -> str:
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end, _ in spans:
        pieces.append(text[cursor:start])
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _end_of_backtick(text: str, start: int) -> int:
    position = start
    while position < len(text) and text[position] != "`":
        position += 2 if text[position] == "\\" else 1
    return min(position, len(text))


def _end_of_paren(text: str, start: int) -> int:
    """Index of the ``)`` that closes a ``$(`` whose body starts at ``start``.

    Quotes are tracked, so a ``)`` inside quotes does not close it, and a
    ``$(`` inside double quotes opens a new level. An unterminated body runs
    to the end of the text.
    """
    depth = 1
    saved: list[str] = []
    quote = ""
    escaped = False
    position = start
    while position < len(text):
        char = text[position]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote == "'":
            if char == "'":
                quote = ""
        elif char == "$" and text[position + 1 : position + 2] == "(":
            saved.append(quote)
            quote = ""
            depth += 1
            position += 1
        elif quote == '"':
            if char == '"':
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "(":
            saved.append("")
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return position
            quote = saved.pop()
        position += 1
    return len(text)


def _substitution_bodies(text: str) -> list[str]:
    """The text inside each backtick pair and ``$(...)`` of ``text``, one level down.

    Substitutions run inside double quotes too, so they are read there. They do
    not run inside single quotes, comments or quoted here document bodies, so
    those are skipped. A nested substitution is returned inside its parent and
    found again when the parent is read.
    """
    skip = {start: end for start, end, quoted in _heredoc_spans(text) if quoted}
    bodies: list[str] = []
    quote = ""
    escaped = False
    position = 0
    while position < len(text):
        if position in skip:
            position = skip[position]
            continue
        char = text[position]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote == "'":
            if char == "'":
                quote = ""
        elif char == "`":
            end = _end_of_backtick(text, position + 1)
            bodies.append(text[position + 1 : end])
            position = end
        elif char == "$" and text[position + 1 : position + 2] == "(":
            end = _end_of_paren(text, position + 2)
            bodies.append(text[position + 2 : end])
            position = end
        elif quote == '"':
            if char == '"':
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (position == 0 or text[position - 1] in " \t\n;&|("):
            newline = text.find("\n", position)
            position = len(text) if newline == -1 else newline
        position += 1
    return bodies


def _write_kind_of(text: str) -> _Result | None:
    """The most serious write kind among the plain parts of ``text``, or ``None``."""
    tokens = _tokenise(_without_heredoc_bodies(text, _heredoc_spans(text)))
    if not tokens:
        return None
    results = [_classify_simple(segment) for segment in _segments(tokens)[0]]
    for kind in _RISK_ORDER:
        for result in results:
            if result[0] == kind:
                return result
    return None


def _substitution_write_kinds(command: str) -> list[_Result]:
    """Write kinds found inside substitutions, to a fixed depth and work budget.

    Past the depth, body count or character budget the rest is not read, so a
    hostile command can only cost a bounded amount of work. Whatever was found
    before the cap is kept, and the command is never a check anyway because it
    contains a substitution.
    """
    found: list[_Result] = []
    queue = [(command, 0)]
    work = len(command)
    count = 0
    for text, depth in queue:
        if depth >= _MAX_SUBSTITUTION_DEPTH:
            continue
        for body in _substitution_bodies(text):
            count += 1
            work += len(body)
            if count > _MAX_SUBSTITUTION_BODIES or work > _MAX_SUBSTITUTION_WORK:
                return found
            kind = _write_kind_of(body)
            if kind is not None:
                found.append(kind)
            queue.append((body, depth + 1))
    return found


def _classify_command(command: object) -> tuple[str, str]:
    """Fail closed.

    ``read_only``, ``test`` and ``build`` can excuse a later step, so they are
    given only to a command that is one plain simple command (no shell
    operator of any kind) from the explicit lists above, with no write flag.
    Every part of a compound command is still looked at for a write kind, so a
    ``git push`` hidden after ``&&`` is still a ``git_push``. Anything else is
    ``unknown``.
    """
    if not isinstance(command, str) or not command.strip() or len(command) > _MAX_COMMAND_CHARS:
        return "unknown", "unknown"
    tokens = _tokenise(_without_heredoc_bodies(command, _heredoc_spans(command)))
    if not tokens:
        return "unknown", "unknown"
    segments, _ = _segments(tokens)
    results = [_classify_simple(segment) for segment in segments]
    # A substitution runs whatever is inside it, so its write kind counts too.
    results.extend(_substitution_write_kinds(command))
    for kind in _RISK_ORDER:
        for result in results:
            if result[0] == kind:
                return result
    if len(results) == 1 and results[0][0] in _SAFE_ORDER and not _has_shell_operators(command):
        return results[0]
    return "unknown", "unknown"


# --------------------------------------------------------------------------- #
# Reading raw transcripts (before redaction)
# --------------------------------------------------------------------------- #

_CALL_BLOCK_TYPES = frozenset({"tool_use", "toolCall"})
_CODEX_CALL_TYPES = frozenset({"function_call", "custom_tool_call"})
_CODEX_OUTPUT_TYPES = frozenset({"function_call_output", "custom_tool_call_output"})
_MAX_DEPTH = 64
_OPENCLAW_FAIL_STATUSES = frozenset({"error", "failed", "failure", "timeout", "timed_out"})


def _command_from_input(value: object) -> str | None:
    """The command string a shell tool input carries, or ``None`` when hidden."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if not isinstance(value, Mapping):
        return None
    for key in ("command", "cmd"):
        command = value.get(key)
        if isinstance(command, str):
            return None if command.startswith("<REDACTED") else command
        if isinstance(command, list) and command and all(isinstance(p, str) for p in command):
            if (
                len(command) >= 3
                and command[0] in {"bash", "sh", "zsh"}
                and command[1] in {"-c", "-lc", "-ic"}
            ):
                return str(command[2])
            return shlex.join(command)
    return None


def _codex_exit_status(output: object) -> str:
    from driftshield.parsers.codex_cli import parse_exit_code

    if isinstance(output, str):
        text = output
    elif isinstance(output, list):
        chunks: list[str] = []
        for item in output:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                chunks.append(item["text"])
        text = "\n".join(chunks)
    else:
        return "unknown"
    code = parse_exit_code(text)
    if code is None:
        return "unknown"
    return "success" if code == 0 else "failure"


def _openclaw_exit_status(message: Mapping[str, Any]) -> str:
    if message.get("isError") is True:
        return "failure"
    details = message.get("details")
    if isinstance(details, Mapping):
        for key in ("exitCode", "exit_code"):
            code = details.get(key)
            if isinstance(code, int) and not isinstance(code, bool):
                return "success" if code == 0 else "failure"
        status = details.get("status")
        if isinstance(status, str) and status.lower() in _OPENCLAW_FAIL_STATUSES:
            return "failure"
    return "success"


def _carriers(
    node: object, skip_keys: Collection[str], depth: int = 0
) -> list[tuple[str, dict[str, Any]]]:
    """Calls and results in document order. Keys in ``skip_keys`` are not entered."""
    found: list[tuple[str, dict[str, Any]]] = []
    if depth > _MAX_DEPTH:
        return found
    if isinstance(node, dict):
        kind = node.get("type")
        if kind in _CALL_BLOCK_TYPES and isinstance(node.get("name"), str):
            found.append(("call", node))
        elif kind in _CODEX_CALL_TYPES and isinstance(node.get("name"), str):
            found.append(("call", node))
        elif kind == "tool_result" or kind in _CODEX_OUTPUT_TYPES:
            found.append(("result", node))
        elif node.get("role") == "toolResult":
            found.append(("result", node))
        for key, child in node.items():
            if key in skip_keys or key == STEP_FACTS_KEY:
                continue
            if isinstance(child, (dict, list)):
                found.extend(_carriers(child, skip_keys, depth + 1))
    elif isinstance(node, list):
        for child in node:
            if isinstance(child, (dict, list)):
                found.extend(_carriers(child, skip_keys, depth + 1))
    return found


def _call_id(node: Mapping[str, Any]) -> str | None:
    for key in ("id", "call_id"):
        value = node.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _result_id_and_status(node: Mapping[str, Any]) -> tuple[str | None, str]:
    kind = node.get("type")
    if kind == "tool_result":
        call_id = node.get("tool_use_id")
        return (call_id if isinstance(call_id, str) else None), (
            "failure" if node.get("is_error") is True else "success"
        )
    if kind in _CODEX_OUTPUT_TYPES:
        call_id = node.get("call_id")
        return (call_id if isinstance(call_id, str) else None), _codex_exit_status(
            node.get("output")
        )
    call_id = node.get("toolCallId")
    return (call_id if isinstance(call_id, str) else None), _openclaw_exit_status(node)


def compute_step_facts(
    transcript: object, *, skip_keys: Collection[str] = ()
) -> dict[int, dict[str, Any]]:
    """Facts for every shell step in a raw transcript, keyed by ``id()`` of its block.

    The raw transcript is not changed. The redactor looks a block up by
    ``id()`` while it rewrites the same objects, and writes ``step_facts`` on
    the redacted block. ``skip_keys`` are keys the redactor drops, so a
    duplicated copy of a step inside a dropped key is not counted twice.

    A step whose command is already hidden (the transcript was redacted
    before and is being analysed again) keeps the facts it carries, validated
    against the fixed lists again; an unmarked one gets ``unknown`` values. A
    step whose command is visible never keeps facts from the input: they are
    recomputed.
    """
    facts_by_node: dict[int, dict[str, Any]] = {}
    pending: dict[str, dict[str, Any]] = {}
    seen_check = False
    for role, node in _carriers(transcript, skip_keys):
        if role == "call":
            name = node["name"]
            if name.lower() not in SHELL_TOOL_NAMES:
                continue
            raw_input = node.get("input") if "input" in node else node.get("arguments")
            command = _command_from_input(raw_input)
            carried = sanitise_step_facts(node.get(STEP_FACTS_KEY))
            if command is None and carried is not None:
                facts = carried
            else:
                kind, target = classify_command(command)
                facts = unknown_facts()
                facts["command_kind"], facts["target_kind"] = kind, target
            facts["checked_before"] = seen_check
            if facts["command_kind"] in _CHECK_KINDS:
                seen_check = True
            facts_by_node[id(node)] = facts
            call_id = _call_id(node)
            if call_id is not None:
                pending[call_id] = facts
        else:
            call_id, status = _result_id_and_status(node)
            if call_id is not None and call_id in pending and status != "unknown":
                pending[call_id]["exit_status"] = status
    return facts_by_node
