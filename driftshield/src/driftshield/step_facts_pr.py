"""Tie the check of a pull request merge to the pull request it merges.

A merge counts as checked only when that same pull request's state, checks, reviews or
comments were read since the previous outside step on that pull request, or earlier in the
same command line. A local read (``git log``, ``ls``), a test, a build and a read of a
different pull request never count for a merge. The pull request number is worked out here,
from the command, on the machine. Only the resulting ``checked_before`` boolean leaves: no
number, repository or command text is stored anywhere.

A read counts inside ``$(...)`` or a loop only when everything in it is an allowlisted read
or a neutral shell word (``sleep``, ``[``, ``test``, ``true``, ``break``). Another command, a
redirect to a file, a nested substitution, a write or anything the classifier does not
recognise makes that part unsafe, and an unsafe part earlier in the command means no read
before the merge can be trusted. When in doubt the answer is "not checked".
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from driftshield.step_facts import (
    _NO_FILE_REDIRECT,
    _RISK_ORDER,
    _classify_chain_part,
    _classify_simple,
    _end_of_paren,
    _segments,
    _split_chain_ops,
    _tokenise,
)

PrRef = tuple[str, str]  # (repository as owner/name or "" for the current one, number)

_VALUE_FLAGS = frozenset(
    {
        "-R", "--repo", "-b", "--body", "-F", "--body-file", "-t", "--title", "--subject",
        "--match-head-commit", "--author-email", "--json", "-q", "--jq", "-T", "--template",
        "-H", "--header", "-X", "--method", "-f", "--raw-field", "--field", "--input",
        "--hostname", "--cache",
    }
)  # fmt: skip
_NUMBER = re.compile(r"\d+")
_PR_URL = re.compile(r"https?://[^/\s]+/([^/\s]+/[^/\s]+)/pull/(\d+)(?:[/?#].*)?$")
_PR_SHORT = re.compile(r"([\w.-]+/[\w.-]+)#(\d+)$")
_API_PATH = re.compile(r"/?repos/([^/]+)/([^/]+)/(pulls|issues)/(\d+)(?:/([A-Za-z_]+))?/?$")
# What counts as a read of a pull request's state, checks, reviews or comments.
_READ_KINDS = frozenset(
    {"pr:view", "pr:checks", "api:pulls/", "api:pulls/reviews", "api:pulls/comments"}
    | {"api:issues/", "api:issues/comments"}
)
# Shell words that run nothing and write nothing. They sit in a loop condition or body.
_SHELL_NEUTRAL = frozenset({"[", "[[", "test", "true", "false", ":", "break", "continue"})
_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
# A variable that changes what a later command runs or where it goes is never a plain read.
_UNSAFE_NAMES = frozenset(
    {"PATH", "IFS", "BASH_ENV", "ENV", "SHELL", "HOME", "PS4", "PROMPT_COMMAND", "CDPATH",
     "SHELLOPTS", "BASHOPTS", "GLOBIGNORE", "TMPDIR", "PWD", "OLDPWD"}
)  # fmt: skip
_UNSAFE_PREFIXES = (
    "LD_", "DYLD_", "GH_", "GITHUB_", "GIT_", "PYTHON", "NODE", "NPM_", "HTTP", "NO_PROXY",
    "ALL_PROXY", "XDG_",
)  # fmt: skip
_LOOP_WORDS = frozenset({"for", "while", "until"})
_STRAY_WORDS = frozenset({"do", "done", "then", "fi", "else", "elif", "esac", "case", "if",
                          "function", "select", "in", "{", "}"})  # fmt: skip
_MAX_STATEMENTS = 200


# --------------------------------------------------------------------------- #
# The pull request a gh command names
# --------------------------------------------------------------------------- #


def _split_flags(rest: list[str]) -> tuple[list[str], str | None]:
    positional: list[str] = []
    repo: str | None = None
    index = 0
    while index < len(rest):
        token = rest[index]
        if token in {"-R", "--repo"} and index + 1 < len(rest):
            repo = rest[index + 1]
            index += 2
        elif token.startswith("--repo="):
            repo = token.split("=", 1)[1]
            index += 1
        elif token.startswith("-R") and not token.startswith("--") and len(token) > 2:
            repo = token[2:]
            index += 1
        elif token in _VALUE_FLAGS and index + 1 < len(rest):
            index += 2
        elif token.startswith("-"):
            index += 1
        else:
            positional.append(token)
            index += 1
    return positional, repo


def _repo_of(owner: str, name: str) -> str:
    if owner == "{owner}" or name == "{repo}":
        return ""  # gh fills these in with the current repository
    return f"{owner}/{name}".lower()


def gh_pr_target(tokens: list[str]) -> tuple[PrRef, str] | None:
    """The pull request a ``gh pr`` or ``gh api`` command names, and what it does to it.

    The second value is ``pr:<action>`` (``pr:merge``, ``pr:view``) or
    ``api:<pulls|issues>/<resource>``. ``None`` when the command names no pull request by a
    literal number: a variable, ``$(...)``, the current branch, or a graphql node id.
    """
    if not tokens or tokens[0] != "gh":
        return None
    positional, repo = _split_flags(tokens[1:])
    if len(positional) >= 2 and positional[0] == "pr":
        action = positional[1]
        for candidate in positional[2:]:
            if _NUMBER.fullmatch(candidate):
                return (repo.lower() if repo else "", candidate), f"pr:{action}"
            for pattern in (_PR_URL, _PR_SHORT):
                match = pattern.match(candidate)
                if match:
                    return (match.group(1).lower(), match.group(2)), f"pr:{action}"
        return None
    if len(positional) >= 2 and positional[0] == "api":
        match = _API_PATH.match(positional[1].split("?", 1)[0])
        if match:
            ref = (_repo_of(match.group(1), match.group(2)), match.group(4))
            return ref, f"api:{match.group(3)}/{match.group(5) or ''}"
    return None


def _pr_read_ref(tokens: list[str]) -> PrRef | None:
    """The pull request a plain allowlisted read reads, or ``None``."""
    target = gh_pr_target(tokens)
    if target is None or target[1] not in _READ_KINDS:
        return None
    return target[0] if _classify_simple(tokens) == ("read_only", "outside_service") else None


def _merge_ref(tokens: list[str]) -> PrRef | None:
    target = gh_pr_target(tokens)
    if target is None or target[1] not in {"pr:merge", "api:pulls/merge"}:
        return None
    return target[0]


# --------------------------------------------------------------------------- #
# Splitting a command line into statements
# --------------------------------------------------------------------------- #


@dataclass
class _Statement:
    text: str
    operator: str  # what follows it: && || | ; or newline, "" for the last


def _skip_to_paren_end(command: str, index: int) -> int:
    return min(_end_of_paren(command, index + 2) + 1, len(command))


def _split_statements(command: str) -> list[_Statement] | None:
    """Top level statements and the operator after each, or ``None`` when not plain.

    Like a plain chain, but ``$(...)`` is kept inside its statement. Brackets, a backtick, a
    comment, a lone ``&``, ``;;``, any redirect that writes a file and a heredoc make it
    ``None``. Quoted text is an argument, not syntax.
    """
    statements: list[_Statement] = []
    current = ""
    quote = ""
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        pair = command[index : index + 2]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote == "'":
            if char == "'":
                quote = ""
        elif char == "`":
            return None
        elif pair == "$(":
            end = _skip_to_paren_end(command, index)
            current += command[index:end]
            index = end
            continue
        elif pair == "${":
            end = command.find("}", index)
            if end < 0:
                return None
            current += command[index : end + 1]
            index = end + 1
            continue
        elif quote == '"':
            if char == '"':
                quote = ""
        elif char in "'\"":
            quote = char
        elif char in "0123456789>&" and (
            not (index > 0 and command[index - 1].isdigit())
            and not (char.isdigit() and index > 0 and command[index - 1].isalnum())
            and (redirect := _NO_FILE_REDIRECT.match(command, index)) is not None
        ):
            index = redirect.end()
            continue
        elif pair in {"&&", "||"}:
            statements.append(_Statement(current, pair))
            current = ""
            index += 2
            continue
        elif char == "|" and command[index + 1 : index + 2] != "&":
            statements.append(_Statement(current, "|"))
            current = ""
            index += 1
            continue
        elif pair == ";;":
            return None
        elif char in ";\n\r":
            statements.append(_Statement(current, ";"))
            current = ""
            index += 1
            continue
        elif char in "&|()<>{}" or (char == "#" and (index == 0 or command[index - 1].isspace())):
            return None
        current += char
        index += 1
    if quote or escaped:
        return None
    statements.append(_Statement(current, ""))
    cleaned = [s for s in statements if s.text.strip()]
    for position, statement in enumerate(statements):
        if statement.operator in {"&&", "||", "|"} and not (
            statement.text.strip() and statements[position + 1].text.strip()
        ):
            return None
    if not cleaned or len(cleaned) > _MAX_STATEMENTS:
        return None
    return [_Statement(s.text.strip(), s.operator) for s in cleaned]


def _replace_substitutions(text: str) -> tuple[str, list[str]] | None:
    """``text`` with each ``$(...)`` replaced by a word, and the bodies. ``None`` for a backtick."""
    out = ""
    bodies: list[str] = []
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote == "'":
            if char == "'":
                quote = ""
        elif char == "`":
            return None
        elif text[index : index + 2] == "$(":
            end = _end_of_paren(text, index + 2)
            if end >= len(text):
                return None
            bodies.append(text[index + 2 : end])
            out += "SUBST"
            index = end + 1
            continue
        elif quote == '"':
            if char == '"':
                quote = ""
        elif char in "'\"":
            quote = char
        out += char
        index += 1
    return out, bodies


# --------------------------------------------------------------------------- #
# What a statement does
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Analysis:
    state: str  # safe, risk or unsafe
    reads: frozenset[PrRef] = frozenset()
    kind: str = ""  # the write kind, for a risk statement
    ref: PrRef | None = None  # the pull request a merge names
    sub_reads: frozenset[PrRef] = frozenset()


_UNSAFE = _Analysis("unsafe")


def _guarded_body_reads(body: str) -> set[PrRef] | None:
    """The pull requests a ``$(...)`` body reads, or ``None`` when the body is not only reads.

    The body must be a plain chain with no nested substitution and no redirect to a file, and
    every part must be an allowlisted read or a neutral word. Anything else, including a part
    that writes or runs code, makes the whole substitution unsafe.
    """
    split = _split_chain_ops(body)
    if split is None:
        return None
    reads: set[PrRef] = set()
    for part in split[0]:
        if not part.strip():
            continue
        kind = _classify_chain_part(part)[0]
        tokens = _tokenise(part)
        segments = _segments(tokens)[0] if tokens else []
        if kind == "neutral" and not all(_is_sleep(segment) for segment in segments):
            return None
        if kind not in {"read_only", "neutral"}:
            return None
        for segment in segments:
            ref = _pr_read_ref(segment)
            if ref is not None:
                reads.add(ref)
    return reads


def _is_sleep(segment: list[str]) -> bool:
    """The only neutral command allowed inside a substitution or a loop."""
    return bool(segment) and segment[0] == "sleep"


def _is_plain_assignment(token: str) -> bool:
    match = _ASSIGNMENT.match(token)
    if match is None:
        return False
    name = match.group(1)
    return name not in _UNSAFE_NAMES and not name.startswith(_UNSAFE_PREFIXES)


def _analyse_simple(text: str, *, strict: bool) -> _Analysis:
    """One statement. ``strict`` (inside a loop) allows only reads and neutral words."""
    replaced = _replace_substitutions(text)
    if replaced is None:
        return _UNSAFE
    stripped, bodies = replaced
    found_reads: set[PrRef] = set()
    for body in bodies:
        found = _guarded_body_reads(body)
        if found is None:
            return _UNSAFE
        found_reads |= found
    sub_reads = frozenset(found_reads)
    tokens = _tokenise(stripped)
    if tokens is None:
        return _UNSAFE
    while tokens and tokens[0] == "!":
        tokens = tokens[1:]
    if not tokens or all(_is_plain_assignment(token) for token in tokens):
        return _Analysis("safe", reads=sub_reads)
    segments, opaque = _segments(tokens)
    if opaque or len(segments) != 1:
        return _UNSAFE
    segment = segments[0]
    if segment[0] in _SHELL_NEUTRAL:
        return _Analysis("safe", reads=sub_reads)
    kind = _classify_simple(segment)[0]
    if kind in _RISK_ORDER:
        return _Analysis("risk", kind=kind, ref=_merge_ref(segment) if kind == "merge" else None,
                         sub_reads=sub_reads)  # fmt: skip
    if kind == "neutral" and strict and not _is_sleep(segment):
        return _UNSAFE  # inside a loop only sleep is allowed: cd, export and the like change later commands
    if kind in {"read_only", "neutral"}:
        ref = _pr_read_ref(segment)
        return _Analysis("safe", reads=sub_reads | ({ref} if ref else frozenset()))
    if kind in {"test", "build"} and not strict:
        return _Analysis("safe", reads=sub_reads)
    return _UNSAFE


def _first_word(text: str) -> str:
    words = text.split(None, 1)
    return words[0] if words else ""


def _loop_end(statements: list[_Statement], start: int) -> int | None:
    for index in range(start + 1, len(statements)):
        word = _first_word(statements[index].text)
        if word in _LOOP_WORDS:
            return None  # nested loops are not read
        if word == "done" and statements[index].text.strip() == "done":
            return index
    return None


def _analyse_loop(statements: list[_Statement]) -> _Analysis:
    """A ``for``, ``while`` or ``until`` loop. Safe only if all of it is reads and neutral words."""
    header = statements[0].text
    keyword = _first_word(header)
    loop_reads: set[PrRef] = set()
    parts: list[str] = []
    position = 1
    if keyword == "for":
        if not re.fullmatch(r"for\s+[A-Za-z_][A-Za-z0-9_]*\s+in(\s.*)?", header):
            return _UNSAFE
        listing = header.split(" in", 1)[1] if " in" in header else ""
        replaced = _replace_substitutions(listing)
        if replaced is None or replaced[1]:
            return _UNSAFE  # a substitution in the word list runs code before the loop
        if _tokenise(listing) is None:
            return _UNSAFE
    else:
        parts.append(header[len(keyword):].strip())
        while position < len(statements) and _first_word(statements[position].text) != "do":
            parts.append(statements[position].text)
            position += 1
    if position >= len(statements) or _first_word(statements[position].text) != "do":
        return _UNSAFE
    parts.append(statements[position].text[len("do"):].strip())
    parts.extend(s.text for s in statements[position + 1 : -1])
    if not any(part.strip() for part in parts):
        return _UNSAFE
    for part in parts:
        if not part.strip():
            continue
        analysis = _analyse_simple(part, strict=True)
        if analysis.state != "safe":
            return _UNSAFE
        loop_reads |= analysis.reads
    return _Analysis("safe", reads=frozenset(loop_reads))


@dataclass
class _Item:
    analysis: _Analysis
    operator: str


def _items(command: str) -> list[_Item] | None:
    statements = _split_statements(command)
    if statements is None:
        return None
    items: list[_Item] = []
    index = 0
    while index < len(statements):
        word = _first_word(statements[index].text)
        if word in _LOOP_WORDS:
            end = _loop_end(statements, index)
            if end is None:
                return None
            items.append(_Item(_analyse_loop(statements[index : end + 1]), statements[end].operator))
            index = end + 1
            continue
        if word in _STRAY_WORDS:
            return None
        items.append(_Item(_analyse_simple(statements[index].text, strict=False), statements[index].operator))
        index += 1
    return items


# --------------------------------------------------------------------------- #
# The three questions step facts ask
# --------------------------------------------------------------------------- #


def merge_tied_check(
    command: str, reads_before: frozenset[PrRef], *, command_kind: str
) -> bool | None:
    """Whether the first write part of ``command``, a merge, was checked by a read of its PR.

    Applies only to a step whose command kind is ``merge``. For any other outside step (a
    deploy, a push to main, a delete, an outside write) the answer is ``None`` without reading
    the command, so those steps keep the scoped rule exactly as before, whatever their command
    looks like (a redirect, a subshell, brackets, ``&``, an ``if`` block).

    ``reads_before`` are the pull requests read since the previous outside step on them. The
    answer is ``True`` only if the first write part is a merge naming a literal pull request
    number and that pull request was read before it (in an earlier step, or earlier in this
    command line, in a statement, a safe ``$(...)`` or a safe loop). ``False`` when it is a
    merge that was not, or when something unsafe runs before it. ``None`` when the first write
    part is not a merge, so the caller applies the scoped rule for other outside steps.
    """
    if command_kind != "merge":
        return None
    items = _items(command)
    if items is None:
        # A merge in a command this reader cannot parse is not checked: the scoped rule
        # would let a local read excuse it.
        return False
    reads = set(reads_before)
    group: set[PrRef] = set()
    for item in items:
        analysis = item.analysis
        if analysis.state == "unsafe":
            return False
        if analysis.state == "risk":
            if analysis.kind != "merge":
                return None
            return analysis.ref is not None and analysis.ref in (reads | analysis.sub_reads)
        group |= analysis.reads
        if item.operator != "|":
            reads |= group  # a read piped into a later part runs with it, not before it
            group = set()
    return False


def command_pr_reads(command: str) -> set[PrRef]:
    """The pull requests a command that is only reads and neutral words reads, else none."""
    items = _items(command)
    if items is None:
        return set()
    reads: set[PrRef] = set()
    for item in items:
        if item.analysis.state != "safe":
            return set()
        reads |= item.analysis.reads
    return reads


def clear_reads(reads: set[PrRef], named: set[PrRef]) -> set[PrRef]:
    """``reads`` without the pull requests an outside step names, across repository forms.

    A step on number N in any repository form clears the read of N with the same repository
    or an unknown one (the current repository, written without ``-R``), so a stale read of
    ``("", 5)`` does not survive ``gh pr merge 5 -R o/r``.
    """
    return {
        read
        for read in reads
        if not any(
            read[1] == ref[1] and (read[0] == ref[0] or "" in {read[0], ref[0]}) for ref in named
        )
    }


def command_pr_refs(command: str) -> set[PrRef]:
    """Every pull request any ``gh`` part of the command names, for clearing earlier reads."""
    tokens = _tokenise(command)
    if not tokens:
        return set()
    refs: set[PrRef] = set()
    for segment in _segments(tokens)[0]:
        target = gh_pr_target(segment)
        if target is not None:
            refs.add(target[0])
    return refs
