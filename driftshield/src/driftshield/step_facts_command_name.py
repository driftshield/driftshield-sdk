"""The name of the command a step ran, with no argument ever kept.

A shell step gets its program and at most two subcommand words (``gh pr merge``,
``git push``, ``pytest``); any other tool gets its tool name (``issue_payment``). Nothing
after the subcommand leaves the machine: no argument, path, URL, message, number or file
content.

Two fixed rules make that hold for any input:

* The program must be in a fixed list of known programs and each subcommand word in a fixed
  list for that program. Anything a user can choose (a script path, a branch, a PR number, a
  make target nobody listed) is never one of those words, so it stops the name where it is.
* The result must match :data:`COMMAND_NAME_SHAPE` (lowercase words of ``[a-z0-9._-]``, at
  most three, each 1 to 32 characters). Anything else becomes :data:`OTHER`. The same shape
  check runs again on any name carried by an already redacted step.
"""

from __future__ import annotations

import posixpath
import re

OTHER = "other"

_WORD = r"[a-z0-9_.-]{1,32}"
COMMAND_NAME_SHAPE = re.compile(rf"{_WORD}(?: {_WORD}){{0,2}}")
_TOOL_NAME_SHAPE = re.compile(_WORD)


def checked_command_name(value: object) -> str:
    """``value`` when it is a well shaped command name, otherwise ``other``."""
    if isinstance(value, str) and COMMAND_NAME_SHAPE.fullmatch(value):
        return value
    return OTHER


def tool_command_name(name: object) -> str:
    """The command name of a tool call that is not a shell step: its tool name, lowercased."""
    if not isinstance(name, str):
        return OTHER
    lowered = name.strip().lower()
    return lowered if _TOOL_NAME_SHAPE.fullmatch(lowered) else OTHER


def _words(*groups: str) -> frozenset[str]:
    return frozenset(word for group in groups for word in group.split())


# program -> {first subcommand word -> second level words (empty: no second word)}.
# A program missing here keeps only its own name.
_GIT = {
    word: frozenset()
    for word in _words(
        "status diff log show add commit push pull fetch merge rebase checkout switch branch tag",
        "reset restore rm mv clean clone init config blame grep ls-files ls-remote describe",
        "cherry-pick revert rev-parse rev-list reflog shortlog merge-base show-ref symbolic-ref",
        "cat-file for-each-ref gc apply am bisect format-patch range-diff sparse-checkout notes",
    )
}
_GIT.update(
    {
        "worktree": _words("add list remove prune move lock unlock repair"),
        "stash": _words("push pop list apply drop show clear"),
        "remote": _words("add remove rename set-url get-url show prune update"),
        "submodule": _words("update init status sync deinit foreach"),
    }
)
_GH_ACTIONS = _words(
    "view list create merge close reopen edit comment checks diff ready review status checkout",
    "delete rerun watch cancel download run enable disable clone fork sync upload login logout",
    "token set develop lock unlock pin unpin transfer repos issues prs commits code refresh",
    "update-branch archive rename",
)
_GH = {
    word: _GH_ACTIONS
    for word in _words(
        "pr issue run workflow repo release label secret variable gist cache project codespace",
        "ruleset auth search extension attestation",
    )
}
_GH.update({word: frozenset() for word in _words("api browse status")})
_JS_SCRIPTS = _words(
    "test build lint dev start typecheck format check e2e preview clean coverage serve watch"
)
_JS = {
    word: frozenset()
    for word in _words(
        "test install i ci build start exec publish add remove uninstall update upgrade audit",
        "outdated ls list init version pack link why dlx x lint dev view info whoami config",
        "cache prune create",
    )
}
_JS["run"] = _JS_SCRIPTS
_DOCKER = {
    word: frozenset()
    for word in _words(
        "build run push pull ps images exec logs stop rm rmi tag login inspect network volume",
        "system start restart kill cp version info",
    )
}
_DOCKER.update(
    {
        "compose": _words("up down build ps logs exec run pull push restart stop config"),
        "buildx": _words("build ls create use inspect bake"),
    }
)
_KUBE = {
    word: frozenset()
    for word in _words(
        "get describe apply delete logs exec create edit patch scale port-forward top install",
        "upgrade uninstall list status template diff history rollback label annotate wait",
    )
}
_KUBE.update(
    {
        "rollout": _words("status restart undo history pause resume"),
        "config": _words("use-context get-contexts current-context view set-context"),
        "repo": _words("add update list remove"),
    }
)
_TERRAFORM = {
    word: frozenset()
    for word in _words(
        "init plan apply destroy validate fmt output import show providers refresh",
        "console graph taint untaint",
    )
}
_TERRAFORM.update(
    {"state": _words("list show mv rm pull push"), "workspace": _words("list select new show")}
)
_UV = {
    word: frozenset()
    for word in _words("sync add remove lock build publish venv export tree init version")
}
_UV.update(
    {
        "pip": _words("install uninstall list freeze show compile sync check tree"),
        "tool": _words("install run list uninstall upgrade"),
        "python": _words("install list find pin"),
    }
)
_PIP = {word: frozenset() for word in _words("install uninstall list freeze show download check")}
_CARGO = {
    word: frozenset()
    for word in _words(
        "build test run check clippy fmt publish add install update bench doc clean new init"
    )
}
_GO = {
    word: frozenset()
    for word in _words("build test run vet get install fmt generate version env clean")
}
_GO.update(
    {"mod": _words("tidy download vendor verify graph why"), "work": _words("init use sync")}
)
_MAKE = {
    word: frozenset()
    for word in _words("test build lint check install clean all deploy release fmt format dev run")
}
_VERCEL = {
    word: frozenset()
    for word in _words(
        "deploy logs ls list inspect promote rollback link pull build alias login whoami curl"
    )
}
_VERCEL.update(
    {
        "env": _words("ls add rm pull"),
        "domains": _words("ls add rm inspect"),
        "project": _words("ls add rm"),
    }
)
_BREW = {
    word: frozenset()
    for word in _words("install upgrade uninstall list update info search outdated cleanup")
}
_BREW["services"] = _words("list start stop restart")
_DRIFTSHIELD = {
    word: frozenset()
    for word in _words("analyze analyse submit capture telemetry serve version report")
}
_AWS_SERVICES = _words(
    "s3 s3api ec2 ecs ecr eks lambda iam sts cloudformation cloudwatch logs dynamodb rds sqs sns",
    "ssm secretsmanager kms route53 cloudfront apigateway apigatewayv2 events stepfunctions",
    "elbv2 autoscaling codebuild codepipeline bedrock bedrock-runtime sso configure",
)
# aws operation words are fixed CLI vocabulary (describe-stacks, get-function, cp, ls).
_AWS_OPERATION = re.compile(r"[a-z][a-z0-9-]{0,31}")

_SUBCOMMANDS: dict[str, dict[str, frozenset[str]]] = {
    "git": _GIT,
    "gh": _GH,
    "npm": _JS,
    "yarn": _JS,
    "pnpm": _JS,
    "bun": _JS,
    "docker": _DOCKER,
    "podman": _DOCKER,
    "kubectl": _KUBE,
    "helm": _KUBE,
    "oc": _KUBE,
    "terraform": _TERRAFORM,
    "tofu": _TERRAFORM,
    "uv": _UV,
    "pip": _PIP,
    "pip3": _PIP,
    "cargo": _CARGO,
    "go": _GO,
    "make": _MAKE,
    "gmake": _MAKE,
    "vercel": _VERCEL,
    "brew": _BREW,
    "driftshield": _DRIFTSHIELD,
}

# Programs whose name alone is kept. Everything the classifier knows is added in
# :func:`known_programs` so the two lists never drift apart.
_EXTRA_PROGRAMS = _words(
    "python python3 py node deno bash sh zsh fish ruby perl php java javac dotnet swift",
    "pytest mypy ruff black isort eslint prettier tsc vitest jest playwright tox nox",
    "aws gcloud az terraform tofu pulumi docker podman kubectl helm oc vercel netlify flyctl",
    "curl wget http https xh ssh scp rsync sftp jq yq sed awk grep rg find ls cat head tail",
    "wc sort uniq cut tr diff echo printf mkdir rm cp mv touch chmod chown ln tar zip unzip",
    "open pbcopy pbpaste which env export source cd pushd popd sleep date kill pkill ps lsof",
    "brew apt apt-get pip pip3 pipx uv uvx poetry npx bunx npm yarn pnpm bun cargo go make",
    "gmake mvn gradle sbt mix bb driftshield sqlite3 psql mysql redis-cli openssl base64",
    "shasum sha256sum md5 xargs tee true false test git gh jj stat file du df realpath",
    "basename dirname timeout launchctl osascript defaults security codex claude",
)


def known_programs() -> frozenset[str]:
    from driftshield import step_facts as sf

    known: set[str] = set(_EXTRA_PROGRAMS) | set(_SUBCOMMANDS)
    for name in (
        "_READ_ONLY_PROGRAMS",
        "_TEST_PROGRAMS",
        "_BUILD_PROGRAMS",
        "_OPAQUE_PROGRAMS",
        "_HELP_TOOLS",
    ):
        known |= {word for word in getattr(sf, name, ()) if isinstance(word, str)}
    return frozenset(word for word in known if _TOOL_NAME_SHAPE.fullmatch(word))


_KNOWN: frozenset[str] | None = None

_GIT_VALUE_FLAGS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace"})


def _program_name(head: str) -> str | None:
    if head.startswith(("./", "../", "~")) or ("/" in head and not head.startswith("/")):
        return None
    program = posixpath.basename(head) if head.startswith("/") else head
    global _KNOWN
    if _KNOWN is None:
        _KNOWN = known_programs()
    return program if program in _KNOWN else None


def name_of_tokens(tokens: list[str]) -> str:
    """The command name of one simple command (already split, prefixes not yet stripped)."""
    from driftshield import step_facts as sf

    tokens = sf._unwrap_runner(sf._strip_prefixes(tokens))
    if not tokens:
        return OTHER
    program = _program_name(tokens[0])
    if program is None:
        return OTHER
    table = _SUBCOMMANDS.get(program)
    if program == "aws":
        rest = sf._drop_value_flags(tokens[1:], sf._VALUE_FLAGS["aws"])
        positional = sf._positionals(rest)
        words = [program]
        if positional[:1] and positional[0] in _AWS_SERVICES:
            words.append(positional[0])
            if positional[1:2] and _AWS_OPERATION.fullmatch(positional[1]):
                words.append(positional[1])
        return checked_command_name(" ".join(words))
    if table is None:
        return checked_command_name(program)
    flags = _GIT_VALUE_FLAGS if program == "git" else sf._VALUE_FLAGS.get(program, sf._NO_FLAGS)
    rest = sf._drop_value_flags(tokens[1:], flags)
    positional = sf._positionals(rest)
    words = [program]
    if positional[:1] and positional[0] in table:
        words.append(positional[0])
        second = table[positional[0]]
        if positional[1:2] and positional[1] in second:
            words.append(positional[1])
    return checked_command_name(" ".join(words))


def shell_command_name(command: object, command_kind: str) -> str:
    """The command name of a shell step whose classified kind is ``command_kind``.

    A command of several parts is named by its first part of that kind (the part that made
    the step what it is), else by its first part that is not a ``cd``, ``pushd`` or ``sleep``.
    An ``unknown`` step is always named by that first part, so a heredoc body or a loop word
    is never picked.
    Never raises.
    """
    try:
        return _shell_command_name(command, command_kind)
    except Exception:  # noqa: BLE001 - a hostile command degrades to other, never raises
        return OTHER


def _shell_command_name(command: object, command_kind: str) -> str:
    from driftshield import step_facts as sf

    if not isinstance(command, str) or not command.strip():
        return OTHER
    if len(command) > sf._MAX_COMMAND_CHARS:
        return OTHER
    tokens = sf._tokenise(command)
    if not tokens:
        return OTHER
    segments, _ = sf._segments(tokens)
    fallback: list[str] | None = None
    for segment in segments:
        kind = sf._classify_simple(segment)[0]
        if kind == "neutral":
            continue
        if kind == command_kind and kind != "unknown":
            return name_of_tokens(segment)
        if fallback is None:
            fallback = segment
    return name_of_tokens(fallback) if fallback is not None else OTHER
