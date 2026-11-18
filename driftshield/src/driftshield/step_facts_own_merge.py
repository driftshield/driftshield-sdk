"""Which merges are merges of the session's own pull request with no read of it since.

Verification failure fires on one shape only: a merge of pull request N when this session
opened N (a ``gh pr create`` whose result shows N's link) or pushed to N's branch, and no read
of N came between the last open or push and the merge. Everything else (deploys, pushes to
main, deletes, other outside writes, merges of pull requests someone else opened) is not
judged by this check.

A read is generous on purpose: any statement that names N and runs ``gh``, ``curl``, a script
or a shell function (which may call ``gh``) counts, inside loops and substitutions too, and so
does a read earlier in the merge command itself. A loop over items such as ``repo:N`` or
``owner/repo/N`` names N for the read inside it. A diff of N is not a read: it shows the
change, not whether the pull request is ready to merge.

The numbers, branches and links are worked out here, on the machine. Only the resulting
``unread_own_merge`` boolean leaves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import shlex

from driftshield.step_facts import _MAIN_BRANCHES, _classify_simple

PrRef = tuple[str, str]  # (repository as owner/name or "" for the current one, number)

_PR_LINK = re.compile(r"https?://[^/\s]+/([^/\s]+/[^/\s]+)/pull/(\d+)")
# Numbers a statement names: links, API paths, ``owner/repo#N``, ``#N`` and bare numbers.
_NAMED_NUMBER = re.compile(
    r"/pulls?/(\d+)|/issues/(\d+)|#(\d+)\b|(?<![\w.:/=@#$-])(\d+)(?![\w.:/-])"
)
# Flags and programs whose next word is a count, a size or a time, never a pull request.
_COUNT_WORDS = frozenset(
    {"sleep", "timeout", "-n", "--limit", "-L", "--tail", "--max-count", "-m", "seq", "head",
     "tail", "--depth", "--interval", "-i", "-c"}
)  # fmt: skip
# The word list of a ``for NAME in ...`` loop, and a list item that names a pull request
# number after a repository: ``repo:N``, ``repo/N`` or ``owner/repo/N``. The read inside the
# loop takes N from the loop variable, so the item is where N is named.
_FOR_LIST = re.compile(r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+([^;\n]*)")
_LIST_ITEM = re.compile(r"(?=[^:/]*[A-Za-z])[\w.-]+(?::|(?:/[\w.-]+)*/)(\d+)")
_DIFF = re.compile(r"\bgh\s+pr\s+diff\b[^;&|\n]*")
_RUNS_GH = re.compile(r"(?<![\w./-])(gh|curl)(?![\w-])")
_LOOP_WORDS = frozenset({"for", "while", "until"})
_SCRIPT_RUNNERS = frozenset({"bash", "sh", "zsh", "source", ".", "python", "python3", "node"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_HEAD_FLAGS = frozenset({"--head", "-H"})
_GH_VALUE_FLAGS = frozenset(
    {"-R", "--repo", "-b", "--body", "-F", "--body-file", "-t", "--title", "--subject",
     "--match-head-commit", "--author-email", "-B", "--base", "-H", "--head", "-a",
     "--assignee", "-l", "--label", "-r", "--reviewer", "-m", "--milestone", "-p", "--project",
     "-T", "--template", "--json", "-q", "--jq", "-X", "--method", "-f", "--field",
     "--raw-field", "--input", "--hostname", "--interval", "-i", "-L", "--limit"}
)  # fmt: skip


_MERGE = re.compile(r"\bgh\s+(?:pr\s+merge\b|api\b[^;&|\n]*?/pulls/\d+/merge\b)")
_CREATE = re.compile(r"\bgh\s+pr\s+create\b")
_PR_READ = re.compile(r"\bgh\s+pr\s+(?:view|checks|status)\b")
_CHECKOUT = re.compile(r"\bgh\s+pr\s+checkout\b")
_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)")


def _gh_call(unit: str, pattern: re.Pattern[str]) -> list[str] | None:
    """The words of the ``gh`` call ``pattern`` finds in ``unit``, from ``gh`` to its end."""
    match = pattern.search(unit)
    if match is None:
        return None
    words: list[str] = []
    for word in _words(unit[match.start() :]):
        if ")" in word and "$(" not in word:
            head = word.split(")", 1)[0]
            if head:
                words.append(head)
            break
        words.append(word)
    return words


def _split_units(command: str) -> list[str]:
    """Statements of ``command`` in order, a whole loop (to its ``done``) as one unit.

    Splits on unquoted ``&&``, ``||``, ``|``, ``;``, ``&`` and newlines, keeping ``$(...)`` and
    quoted text inside the statement. This reader is generous: it never fails, so an odd
    command still yields its statements.
    """
    parts: list[str] = []
    current = ""
    quote = ""
    depth = 0
    index = 0
    while index < len(command):
        char = command[index]
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"' and index + 1 < len(command):
                current += char + command[index + 1]
                index += 2
                continue
        elif char in "'\"":
            quote = char
        elif command.startswith("$(", index):
            depth += 1
            current += "$("
            index += 2
            continue
        elif char == ")" and depth:
            depth -= 1
        elif char == "&" and (command[index - 1 : index] in {">", "<"} or
                              command[index + 1 : index + 2] == ">"):
            pass  # part of a redirect (2>&1, &>file), not a separator
        elif depth == 0 and char in ";&|\n\r":
            parts.append(current)
            current = ""
            index += 1
            continue
        current += char
        index += 1
    parts.append(current)
    statements = [part.strip() for part in parts if part.strip()]
    units: list[str] = []
    loop: list[str] = []
    nesting = 0
    for statement in statements:
        word = statement.split(None, 1)[0]
        if word in _LOOP_WORDS:
            nesting += 1
        if nesting:
            loop.append(statement)
            if word == "done":
                nesting -= 1
                if nesting == 0:
                    units.append("; ".join(loop))
                    loop = []
            continue
        units.append(statement)
    if loop:
        units.append("; ".join(loop))
    return units


def _words(text: str) -> list[str]:
    try:
        return shlex.split(text, comments=False)
    except ValueError:
        return text.split()


def _program(words: list[str]) -> list[str]:
    """``words`` without leading assignments and shell keywords."""
    index = 0
    while index < len(words) and (
        _ASSIGNMENT.match(words[index]) or words[index] in {"do", "then", "else", "if", "!"}
    ):
        index += 1
    return words[index:]


def _gh_parts(words: list[str]) -> tuple[list[str], dict[str, str]]:
    """Positional words and value flags of a ``gh`` command (without the ``gh``)."""
    positional: list[str] = []
    values: dict[str, str] = {}
    index = 1
    while index < len(words):
        word = words[index]
        if "=" in word and word.startswith("--"):
            name, value = word.split("=", 1)
            values[name] = value
        elif word in _GH_VALUE_FLAGS and index + 1 < len(words):
            values[word] = words[index + 1]
            index += 1
        elif not word.startswith("-"):
            positional.append(word)
        index += 1
    return positional, values


def _numbers(text: str) -> set[str]:
    words = text.split()
    skip: set[int] = set()
    position = 0
    for i, word in enumerate(words):
        start = text.find(word, position)
        position = start + len(word)
        if i and words[i - 1] in _COUNT_WORDS:
            skip.add(start)
    found: set[str] = set()
    for match in _NAMED_NUMBER.finditer(text):
        number = next(group for group in match.groups() if group is not None)
        if match.group(4) is not None and match.start(4) in skip:
            continue
        found.add(number.lstrip("0") or "0")
    return found


def _loop_item_numbers(text: str) -> set[str]:
    """Numbers named by ``repo:N`` or ``owner/repo/N`` items of the ``for`` loops in ``text``."""
    found: set[str] = set()
    for items in _FOR_LIST.findall(text):
        for item in items.split():
            match = _LIST_ITEM.fullmatch(item.strip("'\""))
            if match is not None:
                found.add(match.group(1).lstrip("0") or "0")
    return found


def _is_script_or_function(words: list[str]) -> bool:
    """A statement that runs a script, or a name the classifier does not know (a function)."""
    if not words:
        return False
    first = words[0]
    if first in _SCRIPT_RUNNERS and len(words) > 1 and not words[1].startswith("-"):
        return True
    if "/" in first or first.endswith((".sh", ".py")):
        return True
    return _classify_simple(words)[0] == "unknown"


def _push_branches(words: list[str]) -> list[str] | None:
    """Branches a ``git push`` names; ``[]`` for a push of the current branch; else ``None``."""
    if len(words) < 2 or words[0] != "git":
        return None
    index = 1
    while index < len(words) and words[index].startswith("-"):
        index += 2 if words[index] in {"-C", "-c"} else 1
    if index >= len(words) or words[index] != "push":
        return None
    args = words[index + 1 :]
    if any(a in {"--delete", "-d", "--tags", "--all", "--mirror"} for a in args):
        return None
    positional = [a for a in args if not a.startswith("-")]
    branches: list[str] = []
    for ref in positional[1:]:
        if ref.startswith(":"):
            return None
        name = ref.rsplit(":", 1)[-1].removeprefix("refs/heads/").lstrip("+")
        if name and name != "HEAD":
            branches.append(name)
    return branches


@dataclass
class OwnMergeTracker:
    """Walks a run's shell steps in order and answers, per merge, whether it was unread."""

    # Pull requests and branches this session opened or pushed to, with no read since.
    unread_prs: set[PrRef] = field(default_factory=set)
    unread_branches: set[str] = field(default_factory=set)
    branch_of: dict[PrRef, str] = field(default_factory=dict)
    pr_of: dict[str, PrRef] = field(default_factory=dict)
    # The branch (or pull request) a step with no named target works on: the last branch
    # pushed, created or checked out.
    current_branch: str | None = None
    current_pr: PrRef | None = None
    # The branch and pull request last worked on in each checkout a step ``cd``-ed into, so a
    # bare ``git push`` after ``cd`` pushes that checkout's branch, not the last one used.
    place: dict[str, tuple[str | None, PrRef | None]] = field(default_factory=dict)
    # The checkout the current step ``cd``-ed into (``None``: it did not).
    step_dir: str | None = None

    # ------------------------------------------------------------------ #

    def _same(self, a: PrRef, b: PrRef) -> bool:
        return a[1] == b[1] and (a[0] == b[0] or "" in {a[0], b[0]})

    def _find(self, ref: PrRef, pool: set[PrRef]) -> list[PrRef]:
        return [item for item in pool if self._same(item, ref)]

    def _branch_for(self, ref: PrRef) -> str | None:
        for known, branch in self.branch_of.items():
            if self._same(known, ref):
                return branch
        return None

    def _mark_read_number(self, number: str) -> None:
        for ref in [item for item in self.unread_prs if item[1] == number]:
            self.unread_prs.discard(ref)
            branch = self._branch_for(ref)
            if branch:
                self.unread_branches.discard(branch)

    def _mark_read_branch(self, branch: str) -> None:
        self.unread_branches.discard(branch)
        ref = self.pr_of.get(branch)
        if ref is not None:
            for item in self._find(ref, self.unread_prs):
                self.unread_prs.discard(item)

    def _tie(self, ref: PrRef, branch: str | None) -> None:
        if branch and branch not in _MAIN_BRANCHES:
            self.branch_of[ref] = branch
            self.pr_of[branch] = ref

    # ------------------------------------------------------------------ #

    def opened(self, heads: list[str | None], result_text: str) -> None:
        """The ``gh pr create`` calls of one step succeeded.

        ``heads`` holds each create's ``--head`` branch (``None`` for the current branch), in
        order. Each create prints its own link, so the links pair up with the creates in
        order. When the counts differ, only the last link is known to be the last create's.
        """
        links = _PR_LINK.findall(result_text)
        if not links or not heads:
            return
        pairs = zip(heads, links) if len(links) == len(heads) else [(heads[-1], links[-1])]
        for head, (repo, number) in pairs:
            self._opened_one(head, (repo.lower(), number))

    def _opened_one(self, head: str | None, ref: PrRef) -> None:
        branch = head if head is not None else self.current_branch
        self._tie(ref, branch)
        self.unread_prs.add(ref)
        if branch:
            self.unread_branches.discard(branch)  # tracked through the pull request now
        self.current_pr = ref
        if head is not None:
            self.current_branch = head
        self._remember_place()

    def _remember_place(self) -> None:
        if self.step_dir is not None:
            self.place[self.step_dir] = (self.current_branch, self.current_pr)

    def step(self, command: str) -> tuple[bool | None, list[str | None]]:
        """Read one shell step.

        Returns whether a merge in it is an unread merge of the session's own pull request
        (``None`` when the step has no merge), and the ``--head`` value of every
        ``gh pr create`` in it (``None`` for one on the current branch), so the caller can
        pass the create's result to :meth:`opened`.
        """
        verdict: bool | None = None
        creates: list[str | None] = []
        self.step_dir = None
        for unit in _split_units(command):
            words = _program(_words(unit))
            if words[:1] == ["cd"] and len(words) == 2:
                self.step_dir = words[1].rstrip("/")
                continue
            merge = _gh_call(unit, _MERGE)
            if merge is not None:
                # A read inside a substitution in the merge statement runs before the merge.
                for body in _SUBSTITUTION.findall(unit):
                    if not _MERGE.search(body):
                        self._read(body)
                unread = self._judge_merge(*_gh_parts(merge))
                verdict = bool(verdict) or unread
                continue
            create = _gh_call(unit, _CREATE)
            if create is not None:
                values = _gh_parts(create)[1]
                head = values.get("--head", values.get("-H"))
                creates.append(head.rsplit(":", 1)[-1] if head else None)
                continue
            checkout = _gh_call(unit, _CHECKOUT)
            if checkout is not None:
                self._checked_out(*_gh_parts(checkout))
                continue
            branches = _push_branches(words)
            if branches is not None:
                self._pushed(branches)
                self._remember_place()
                continue
            if words[:2] in (["git", "checkout"], ["git", "switch"]):
                names = [w for w in words[2:] if not w.startswith("-")]
                if names:
                    self.current_branch = names[-1]
                    self.current_pr = self.pr_of.get(names[-1])
                    self._remember_place()
                continue
            self._read(unit)
        return verdict, creates

    def _checked_out(self, positional: list[str], values: dict[str, str]) -> None:
        if len(positional) < 3:
            return
        target = positional[2]
        link = _PR_LINK.search(target)
        number = link.group(2) if link else target.lstrip("#")
        if number.isdigit():
            repo = link.group(1).lower() if link else values.get("-R", values.get("--repo", ""))
            self.current_pr = (repo.lower(), number)
            self.current_branch = self._branch_for(self.current_pr)
        else:
            self.current_branch, self.current_pr = target, self.pr_of.get(target)
        self._remember_place()

    def _pushed(self, branches: list[str]) -> None:
        if not branches and self.step_dir is not None:
            # A bare push in a checkout the step ``cd``-ed into pushes that checkout's branch.
            # One never seen before pushes a branch this run cannot name: nothing reopens.
            self.current_branch, self.current_pr = self.place.get(self.step_dir, (None, None))
            if self.current_branch is None and self.current_pr is None:
                return
        if not branches:
            if self.current_branch is None:
                if self.current_pr is not None:
                    self.unread_prs.add(self.current_pr)
                return
            branches = [self.current_branch]
        for branch in branches:
            if branch in _MAIN_BRANCHES:
                continue
            self.current_branch = branch
            ref = self.pr_of.get(branch)
            if ref is not None:
                self.unread_prs.add(ref)
                self.current_pr = ref
            else:
                self.unread_branches.add(branch)
                self.current_pr = None

    def _read(self, unit: str) -> None:
        text = _DIFF.sub(" ", unit)
        if not (_RUNS_GH.search(text) or _is_script_or_function(_program(_words(text)))):
            return
        for number in _numbers(text) | _loop_item_numbers(text):
            self._mark_read_number(number)
        branches = set(self.unread_branches) | {
            branch for ref in self.unread_prs if (branch := self._branch_for(ref)) is not None
        }
        for branch in branches:
            if re.search(rf"(?<![\w./-]){re.escape(branch)}(?![\w./-])", text):
                self._mark_read_branch(branch)
        # ``gh pr view`` or ``gh pr checks`` with no target reads the current branch's pull
        # request.
        read = _gh_call(text, _PR_READ)
        if read is not None and len(_gh_parts(read)[0]) == 2:
            if self.current_pr is not None:
                for item in self._find(self.current_pr, self.unread_prs):
                    self.unread_prs.discard(item)
            if self.current_branch is not None:
                self._mark_read_branch(self.current_branch)

    def _judge_merge(self, positional: list[str], values: dict[str, str]) -> bool:
        repo = values.get("-R", values.get("--repo", "")).lower()
        ref: PrRef | None = None
        branch: str | None = None
        if positional[0] == "api":
            match = re.search(r"repos/([^/]+)/([^/]+)/pulls/(\d+)/merge", " ".join(positional))
            if match is None:
                return False
            owner_repo = f"{match.group(1)}/{match.group(2)}".lower()
            ref = ("" if "{" in owner_repo else owner_repo, match.group(3))
        elif len(positional) > 2:
            target = positional[2]
            link = _PR_LINK.search(target)
            if link:
                ref = (link.group(1).lower(), link.group(2))
            elif target.lstrip("#").isdigit():
                ref = (repo, target.lstrip("#"))
            elif "#" in target and target.split("#", 1)[1].isdigit():
                ref = (target.split("#", 1)[0].lower(), target.split("#", 1)[1])
            elif target.startswith("$"):
                return False  # a target in a variable is never judged
            else:
                branch = target
        else:
            ref, branch = self.current_pr, self.current_branch
        if ref is None and branch is not None:
            ref = self.pr_of.get(branch)
        if branch is None and ref is not None:
            branch = self._branch_for(ref)
        unread = bool(ref is not None and self._find(ref, self.unread_prs)) or bool(
            branch is not None and branch in self.unread_branches
        )
        # A merge ends the pull request's life in this session: it is not unread any more.
        if ref is not None:
            for item in self._find(ref, self.unread_prs):
                self.unread_prs.discard(item)
        if branch is not None:
            self.unread_branches.discard(branch)
        return unread
