"""Destructive-command and dangerous-binary blocker for tool arguments (OWASP LLM06).

Commands are de-obfuscated before matching: ANSI-C quoting (``$'\\x72m'``), quote and
backslash concatenation (``r''m``, ``r\\m``), ``$IFS`` and empty expansions, brace lists,
line continuations and Unicode/whitespace tricks. Binaries are matched by basename in
command position (after env assignments and wrappers such as ``sudo``, ``env``,
``timeout``), so path spoofing (``/usr/bin/rm``, ``../../bin//rm``) and glob spoofing
(``/???/r?``) are caught too.

:class:`CommandGuard` applies the blacklist to command arguments of tool calls as a
decorator over any ``ToolCallGuard``.
"""

import fnmatch
import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from pydantic import JsonValue

from llm_security_shield.schemas import PolicyAction, ToolCall, ToolCallDecision
from llm_security_shield.tools import DEFAULT_COMMAND_ARGUMENTS, ToolCallGuard

_DESTRUCTIVE = "destructive"
_PERMISSIONS = "permission change"
_NETWORK = "network or exfiltration"
_INTERPRETER = "arbitrary code execution"
_PRIVILEGE = "privilege escalation"
_SYSTEM = "system control"
_REVERSE_SHELL = "reverse shell"

#: Binary basename -> reason it is blocked.
DEFAULT_BLOCKED_BINARIES: Final[Mapping[str, str]] = {
    **dict.fromkeys(
        (
            "rm", "rmdir", "unlink", "shred", "srm", "wipe", "dd", "mkfs", "mke2fs",
            "mkswap", "fdisk", "sfdisk", "gdisk", "parted", "wipefs", "truncate", "blkdiscard",
        ),
        _DESTRUCTIVE,
    ),
    **dict.fromkeys(("chmod", "chown", "chgrp", "chattr", "setfacl"), _PERMISSIONS),
    **dict.fromkeys(
        (
            "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp",
            "scp", "sftp", "rsync", "ssh", "nmap",
        ),
        _NETWORK,
    ),
    **dict.fromkeys(("perl", "eval", "source"), _INTERPRETER),
    **dict.fromkeys(("sudo", "su", "doas", "pkexec"), _PRIVILEGE),
    **dict.fromkeys(
        (
            "shutdown", "reboot", "halt", "poweroff", "init", "systemctl", "kill", "killall",
            "pkill", "crontab", "mount", "umount", "iptables", "useradd", "userdel",
            "usermod", "passwd", "insmod", "rmmod", "modprobe",
        ),
        _SYSTEM,
    ),
    "mkfifo": _REVERSE_SHELL,
}  # fmt: skip

#: Interpreters that are allowed alone but not with inline-code or interactive flags.
INLINE_CODE_FLAGS: Final[Mapping[str, frozenset[str]]] = {
    "python": frozenset({"-c"}),
    "pypy": frozenset({"-c"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "deno": frozenset({"eval"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
    "osascript": frozenset({"-e"}),
    **dict.fromkeys(
        ("bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh"), frozenset({"-c", "-i"})
    ),
    **dict.fromkeys(
        ("powershell", "pwsh"),
        frozenset({"-c", "-command", "-e", "-enc", "-encodedcommand"}),
    ),
}

#: Prefix commands whose arguments are themselves a command.
_WRAPPERS: Final = frozenset(
    {
        "command", "exec", "nohup", "time", "nice", "ionice", "timeout", "xargs", "env",
        "busybox", "stdbuf", "setsid", "strace", "watch", "chroot", "then", "do", "else",
        "if", "while", "until", "!", "builtin",
    }
)  # fmt: skip

_DANGEROUS_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, str], ...]] = (
    (re.compile(r"/dev/(?:tcp|udp)/", re.I), "dev_socket", _REVERSE_SHELL),
    (re.compile(r":\s*\(\s*\)\s*\{"), "fork_bomb", _DESTRUCTIVE),
    (re.compile(r">\s*/dev/(?:sd|hd|nvme|disk|mmcblk|xvd)", re.I), "raw_disk_write", _DESTRUCTIVE),
    (re.compile(r"\bof=/dev/", re.I), "raw_disk_write", _DESTRUCTIVE),
    (re.compile(r"--no-preserve-root", re.I), "no_preserve_root", _DESTRUCTIVE),
    (
        re.compile(
            r"\b(?:base64|xxd|openssl|uudecode)\b[^|]*\|\s*(?:\w*/)*(?:ba|z|da|k)?sh\b", re.I
        ),
        "decode_and_execute",
        _INTERPRETER,
    ),
    (
        re.compile(r"\bfind\b.*\s-(?:delete|exec|execdir|ok|okdir)\b", re.I),
        "find_exec",
        _DESTRUCTIVE,
    ),
    (re.compile(r"\$\(|`"), "command_substitution", _INTERPRETER),
    (re.compile(r"\$\{[^}]*[:/#%^,]"), "parameter_expansion_obfuscation", _INTERPRETER),
)

_ANSI_C_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)
_ANSI_C_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", re.S)
_ANSI_C_SIMPLE: Final = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b"}
_LINE_CONTINUATION = re.compile(r"\\\r?\n")
_IFS = re.compile(r"\$\{?IFS(?:[%#][^}]*)?\}?(?:\$\d)?")
_EMPTY_EXPANSION = re.compile(r"\$(?:[@*#?!$0-9]|\{[@*#?!$0-9]\})")
_BRACE_LIST = re.compile(r"\{([^{}\s]*,[^{}]*)\}")
_QUOTES = re.compile(r"[\"']")
_ESCAPED_CHAR = re.compile(r"\\(.)", re.S)
_WHITESPACE = re.compile(r"\s+")
_SEPARATORS = re.compile(r"&&|\|\||[;|&\n()`]|\$\(")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VERSION_SUFFIX = re.compile(r"(?<=[a-z])[\d.]+$")
_GLOB_CHARS: Final = frozenset("?*[")


@dataclass(frozen=True, slots=True)
class CommandViolation:
    """Why a command was blocked. ``binary`` is set when a specific binary matched."""

    rule: str
    reason: str
    binary: str | None = None

    def describe(self) -> str:
        """Short client-safe explanation."""
        target = f" '{self.binary}'" if self.binary else ""
        return f"blocked command{target}: {self.reason} ({self.rule})"


def _decode_ansi_c(match: re.Match[str]) -> str:
    def escape(m: re.Match[str]) -> str:
        code = m.group(1)
        if code[0] == "x":
            return chr(int(code[1:], 16))
        if code[0] in "01234567":
            return chr(int(code, 8))
        return _ANSI_C_SIMPLE.get(code, code)

    return _ANSI_C_ESCAPE.sub(escape, match.group(1))


def normalize_command(command: str) -> str:
    """Undo common shell obfuscation so binaries can be matched by name."""
    text = unicodedata.normalize("NFKC", command)
    text = _LINE_CONTINUATION.sub("", text)
    text = _ANSI_C_QUOTE.sub(_decode_ansi_c, text)
    text = _IFS.sub(" ", text)
    text = _EMPTY_EXPANSION.sub("", text)
    text = _BRACE_LIST.sub(lambda m: " ".join(m.group(1).split(",")), text)
    text = _QUOTES.sub("", text)
    text = _ESCAPED_CHAR.sub(r"\1", text)
    return _WHITESPACE.sub(" ", text).strip()


def _binary_name(token: str) -> str:
    """Basename, lower-cased (case-insensitive filesystems exist), version-stripped."""
    name = token.rsplit("/", 1)[-1].lower()
    return _VERSION_SUFFIX.sub("", name)


def _command_tokens(segment: str) -> list[str]:
    """Tokens from the command position onward, skipping env assignments and wrappers."""
    tokens = segment.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        name = _binary_name(token)
        if (
            _ENV_ASSIGNMENT.match(token)
            or token.startswith("-")
            or token.isdigit()
            or name in _WRAPPERS
        ):
            index += 1
        else:
            break
    return tokens[index:]


class CommandBlacklist:
    """Blocks dangerous binaries, interpreter one-liners and reverse-shell constructs."""

    def __init__(
        self,
        *,
        blocked_binaries: Mapping[str, str] = DEFAULT_BLOCKED_BINARIES,
        extra_binaries: Mapping[str, str] | None = None,
        allowed_binaries: Iterable[str] = (),
    ) -> None:
        allowed = {name.lower() for name in allowed_binaries}
        merged = {**blocked_binaries, **(extra_binaries or {})}
        self._blocked = {k.lower(): v for k, v in merged.items() if k.lower() not in allowed}
        self._inline = {k: v for k, v in INLINE_CODE_FLAGS.items() if k not in allowed}

    def check(self, command: str | Sequence[str]) -> CommandViolation | None:
        """Return the first violation in ``command`` (a string or an argv list)."""
        raw = command if isinstance(command, str) else " ".join(command)
        normalized = normalize_command(raw)
        for pattern, rule, reason in _DANGEROUS_PATTERNS:
            if pattern.search(raw) or pattern.search(normalized):
                return CommandViolation(rule=rule, reason=reason)
        for segment in _SEPARATORS.split(normalized):
            if violation := self._check_segment(segment):
                return violation
        return None

    def _check_segment(self, segment: str) -> CommandViolation | None:
        tokens = _command_tokens(segment)
        if not tokens:
            return None
        name = _binary_name(tokens[0])
        if any(char in _GLOB_CHARS for char in name):
            if matched := next((b for b in self._blocked if fnmatch.fnmatchcase(b, name)), None):
                return CommandViolation("glob_spoofed_binary", self._blocked[matched], matched)
            return None
        stem = name.split(".", 1)[0]  # mkfs.ext4 -> mkfs
        for candidate in dict.fromkeys((name, stem)):
            if reason := self._blocked.get(candidate):
                return CommandViolation("blocked_binary", reason, candidate)
        flags = self._inline.get(stem)
        if flags and any(_matches_flag(arg.lower(), flags) for arg in tokens[1:]):
            return CommandViolation("inline_interpreter", _INTERPRETER, stem)
        return None


def _matches_flag(arg: str, flags: frozenset[str]) -> bool:
    if arg in flags:
        return True
    # Bundled short options, e.g. "-ic" contains "-i" and "-c".
    short = {f[1] for f in flags if len(f) == 2 and f.startswith("-")}  # noqa: PLR2004
    return arg.startswith("-") and not arg.startswith("--") and bool(short & set(arg[1:]))


def _command_values(
    arguments: dict[str, JsonValue], keys: frozenset[str]
) -> Iterator[tuple[str, str | list[str]]]:
    """``(key, command)`` for every command-bearing argument, at any depth.

    A list of strings under a command key is treated as one argv.
    """
    stack: list[tuple[str | None, JsonValue]] = []
    stack.extend(arguments.items())
    while stack:
        key, value = stack.pop()
        is_command = key is not None and key.lower() in keys
        if isinstance(value, str) and is_command:
            yield key or "", value
        elif isinstance(value, list):
            if is_command and value and all(isinstance(v, str) for v in value):
                yield key or "", [v for v in value if isinstance(v, str)]
            else:
                stack.extend((key, item) for item in value)
        elif isinstance(value, dict):
            stack.extend(value.items())


class CommandGuard:
    """``ToolCallGuard`` decorator: the inner guard decides, then commands are vetted."""

    def __init__(
        self,
        inner: ToolCallGuard,
        blacklist: CommandBlacklist | None = None,
        *,
        command_arguments: Iterable[str] = DEFAULT_COMMAND_ARGUMENTS,
    ) -> None:
        self._inner = inner
        self._blacklist = CommandBlacklist() if blacklist is None else blacklist
        self._keys = frozenset(name.lower() for name in command_arguments)

    def evaluate(self, call: ToolCall) -> ToolCallDecision:
        """Inner decision, downgraded to deny when a command argument is dangerous."""
        return self._vet(call, self._inner.evaluate(call))

    def evaluate_all(self, calls: Sequence[ToolCall]) -> tuple[ToolCallDecision, ...]:
        """Inner batch decisions (call limits included), each vetted the same way."""
        decisions = self._inner.evaluate_all(calls)
        return tuple(self._vet(c, d) for c, d in zip(calls, decisions, strict=True))

    def _vet(self, call: ToolCall, decision: ToolCallDecision) -> ToolCallDecision:
        if decision.action is PolicyAction.DENY:
            return decision
        for key, command in _command_values(call.arguments, self._keys):
            if violation := self._blacklist.check(command):
                return ToolCallDecision(
                    tool_name=call.name,
                    action=PolicyAction.DENY,
                    reason=f"{violation.describe()} in argument '{key}'"[:256],
                )
        return decision
