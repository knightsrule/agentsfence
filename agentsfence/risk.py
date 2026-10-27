"""Tool risk classification, independent of individual tool names.

Three layers, first hit wins:

1. explicit per-tool mapping (``tools:`` in defaults.yaml), optionally refined
   by an argument value (``arg_risk``) or, for ``terminal``, by the shell
   command classifier;
2. glob patterns (``patterns:``);
3. verb inference from the tool name (``mcp_gmail_send_message`` →
   ``email.send`` / COMMUNICATION).

Anything that yields no signal is ``UNKNOWN``, which the evaluator never
treats as safe.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import shlex
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import RiskClass, ToolProfile

_ACTION_NAMES: dict[RiskClass, str] = {
    RiskClass.READ: "read",
    RiskClass.LOCAL_WRITE: "write",
    RiskClass.EXTERNAL_WRITE: "write",
    RiskClass.COMMUNICATION: "send",
    RiskClass.DELETE: "delete",
    RiskClass.PERMISSION_CHANGE: "share",
    RiskClass.FINANCIAL: "pay",
    RiskClass.EXECUTION: "exec",
    RiskClass.UNKNOWN: "unknown",
}

# Priority when several strong verbs appear in one name.
_STRONG_ORDER = (
    RiskClass.FINANCIAL,
    RiskClass.PERMISSION_CHANGE,
    RiskClass.DELETE,
    RiskClass.COMMUNICATION,
    RiskClass.EXECUTION,
)

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^a-zA-Z0-9]+")


def tokenize(name: str) -> list[str]:
    parts = _SPLIT.split(_CAMEL.sub("_", name))
    return [p.lower() for p in parts if p]


# ---------------------------------------------------------------------------
# Shell command sub-classification (terminal tool)
# ---------------------------------------------------------------------------

_SAFE_READ_CMDS = frozenset(
    {
        "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "wc", "pwd", "echo",
        "which", "whereis", "file", "stat", "du", "df", "date", "whoami", "uname", "sort",
        "uniq", "cut", "tr", "tree", "jq", "yq", "less", "more", "basename", "dirname",
        "realpath", "readlink", "id", "hostname", "printf", "column", "nl", "diff", "cmp",
        "md5", "md5sum", "sha256sum", "shasum", "true", "test", "ps", "uptime", "free",
    }
)
#: Options that turn an otherwise read-only command into a writer or a launcher:
#: (long options, short option letters).
_READ_CMD_WRITE_OPTS: dict[str, tuple[frozenset[str], str]] = {
    "sort": (frozenset({"--output"}), "o"),
    "tree": (frozenset({"--output"}), "o"),
    "rg": (frozenset({"--pre", "--pre-glob"}), ""),
    "yq": (frozenset({"--inplace"}), "i"),
    "date": (frozenset({"--set"}), "s"),
    "file": (frozenset({"--compile"}), "C"),
}
_HOSTNAME_READ_OPTS = frozenset({"-s", "-f", "-d", "-i", "-I", "-a", "-A", "--short", "--fqdn", "--long", "--domain", "--ip-address", "--all-ip-addresses", "--alias"})
_SYSTEM_BIN_DIRS = ("/bin/", "/usr/bin/", "/usr/local/bin/", "/opt/homebrew/bin/", "/sbin/", "/usr/sbin/")
_DELETE_CMDS = frozenset({"rm", "rmdir", "shred", "unlink", "srm"})
_PERMISSION_CMDS = frozenset({"chmod", "chown", "chgrp", "sudo", "su", "doas", "setfacl", "passwd", "usermod", "visudo"})
_NETWORK_WRITE_CMDS = frozenset({"scp", "sftp", "ssh", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "mail", "sendmail", "mutt"})
_FIND_DANGEROUS = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"})
_CURL_WRITE_FLAGS = ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form", "-T", "--upload-file", "--json")
_SHELL_META = re.compile(r"[;&<>`$(){}\n\\]")
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.IGNORECASE)

# git subcommands that only read, unless given an output/launcher option.
_GIT_READ_SUBCMDS = frozenset({"status", "log", "diff", "show", "rev-parse", "ls-files", "ls-tree", "blame", "describe", "cat-file", "shortlog"})
_GIT_BRANCH_MUTATING = frozenset({"-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy", "-f", "--force", "-u", "--set-upstream-to", "--unset-upstream", "--edit-description", "-t", "--track", "--no-track", "--create-reflog"})
_GIT_BRANCH_DELETE = frozenset({"-d", "-D", "--delete"})
#: git global options that take a separate value (and, for the long ones, ``--opt=value``).
_GIT_GLOBAL_VALUE_OPTS = frozenset({"-C", "--git-dir", "--work-tree", "--namespace"})
#: git global options without a value that neither load configuration nor name a program.
_GIT_GLOBAL_FLAGS = frozenset({
    "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
    "--no-advice", "--bare", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs",
})


def classify_shell(command: str) -> tuple[RiskClass, str]:
    """Classify a shell command string. Conservative: anything unusual is EXECUTION."""
    cmd = (command or "").strip()
    if not cmd:
        return RiskClass.EXECUTION, "shell.exec"
    segments = [s.strip() for s in re.split(r"\|\||&&|[|;\n&]", cmd) if s.strip()]
    worst = RiskClass.READ
    capability = "shell.read"
    for segment in segments:
        risk, cap = _classify_segment(segment)
        if _rank(risk) > _rank(worst):
            worst, capability = risk, cap
    # Compound commands / substitutions / redirection can hide anything.
    if _SHELL_META.search(cmd) and worst is RiskClass.READ:
        return RiskClass.EXECUTION, "shell.exec"
    return worst, capability


def _rank(risk: RiskClass) -> int:
    order = [
        RiskClass.READ, RiskClass.LOCAL_WRITE, RiskClass.EXECUTION, RiskClass.EXTERNAL_WRITE,
        RiskClass.COMMUNICATION, RiskClass.DELETE, RiskClass.PERMISSION_CHANGE, RiskClass.FINANCIAL,
    ]
    return order.index(risk) if risk in order else len(order)


def _has_opt(args: list[str], longs: frozenset[str], shorts: str) -> bool:
    for a in args:
        if a == "--":
            break
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if name in longs:
                return True
        elif a.startswith("-") and len(a) > 1 and shorts and any(ch in a[1:] for ch in shorts):
            return True
    return False


def _positional(args: list[str]) -> list[str]:
    return [a for a in args if not a.startswith("-")]


def _system_program(path: str) -> bool:
    """A path directly inside a system bin directory, with no "." or ".." to resolve elsewhere."""
    head, _, name = path.rpartition("/")
    if not name or any(part in (".", "..") for part in head.split("/")):
        return False
    return head + "/" in _SYSTEM_BIN_DIRS


def _classify_segment(segment: str) -> tuple[RiskClass, str]:
    try:
        argv = shlex.split(segment)
    except ValueError:
        return RiskClass.EXECUTION, "shell.exec"
    if not argv:
        return RiskClass.EXECUTION, "shell.exec"
    # FOO=bar cmd ...: variables such as LD_PRELOAD, LESSOPEN, PAGER or GIT_* can
    # make any "read" command run arbitrary code.
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
        return RiskClass.EXECUTION, "shell.exec"
    # A program named like a safe command but living somewhere else (./ls, /tmp/x/cat,
    # /usr/bin/../../tmp/ls) is just an arbitrary program.
    if "/" in argv[0] and not _system_program(argv[0]):
        return RiskClass.EXECUTION, "shell.exec"
    prog = Path(argv[0]).name
    rest = argv[1:]
    if prog in _PERMISSION_CMDS:
        return RiskClass.PERMISSION_CHANGE, "shell.permission"
    if prog in _DELETE_CMDS:
        return RiskClass.DELETE, "shell.delete"
    if prog == "git":
        return _classify_git(rest)
    if prog in {"curl", "wget", "http", "https", "xh"}:
        if any(a == f or a.startswith(f + "=") for a in rest for f in _CURL_WRITE_FLAGS):
            return RiskClass.EXTERNAL_WRITE, "shell.network_write"
        for i, a in enumerate(rest):
            if a in {"-X", "--request", "--method"} and i + 1 < len(rest) and rest[i + 1].upper() != "GET":
                return RiskClass.EXTERNAL_WRITE, "shell.network_write"
            if a.startswith("-X") and len(a) > 2 and a[2:].upper() != "GET":
                return RiskClass.EXTERNAL_WRITE, "shell.network_write"
        if prog in {"http", "https", "xh"} and rest and rest[0].upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            return RiskClass.EXTERNAL_WRITE, "shell.network_write"
        return RiskClass.EXECUTION, "shell.network_read"
    if prog in _NETWORK_WRITE_CMDS:
        return RiskClass.EXTERNAL_WRITE, "shell.network_write"
    if prog == "find":
        if any(a in _FIND_DANGEROUS for a in rest):
            return RiskClass.EXECUTION, "shell.exec"
        return RiskClass.READ, "shell.read"
    if prog in _READ_CMD_WRITE_OPTS:
        longs, shorts = _READ_CMD_WRITE_OPTS[prog]
        if _has_opt(rest, longs, shorts):
            return (RiskClass.EXECUTION, "shell.exec") if prog == "rg" else (RiskClass.LOCAL_WRITE, "shell.write")
    if prog == "hostname" and any(a not in _HOSTNAME_READ_OPTS for a in rest):
        return RiskClass.EXECUTION, "shell.exec"
    if prog == "uniq" and len(_positional(rest)) >= 2:  # uniq INPUT OUTPUT writes OUTPUT
        return RiskClass.LOCAL_WRITE, "shell.write"
    if prog in _SAFE_READ_CMDS:
        return RiskClass.READ, "shell.read"
    return RiskClass.EXECUTION, "shell.exec"


def _git_split(rest: list[str]) -> tuple[str, list[str]] | None:
    """``(subcommand, its arguments)``, or None when a global option is not a known safe one.

    Only global options known to select a repository or control paging are
    skipped. -c / -c<name>=<value> / --config-env / --exec-path can point git at
    arbitrary programs (pager, fsmonitor, diff drivers, hooks), and an
    unrecognized option may do the same in some git version.
    """
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        opt = rest[i]
        if opt in _GIT_GLOBAL_VALUE_OPTS:
            i += 2
        elif opt in _GIT_GLOBAL_FLAGS or (opt.partition("=")[0] in _GIT_GLOBAL_VALUE_OPTS and opt.startswith("--") and "=" in opt):
            i += 1
        else:
            return None
    if i >= len(rest):
        return None
    return rest[i], rest[i + 1 :]


def _classify_git(rest: list[str]) -> tuple[RiskClass, str]:
    # An unknown global option or a missing subcommand is execution (see _git_split).
    split = _git_split(rest)
    if split is None:
        return RiskClass.EXECUTION, "shell.exec"
    sub, args = split
    pos = _positional(args)
    if sub in {"push", "send-email", "request-pull"}:
        return RiskClass.EXTERNAL_WRITE, "shell.network_write"
    if sub == "clean" or sub == "restore" or (sub == "reset" and "--hard" in args):
        return RiskClass.DELETE, "shell.delete"
    if sub == "checkout" and ("--" in args or "-f" in args or "--force" in args):
        return RiskClass.DELETE, "shell.delete"
    if sub == "branch":
        if any(a in _GIT_BRANCH_DELETE for a in args):
            return RiskClass.DELETE, "shell.delete"
        listing = "-l" in args or "--list" in args
        if any(a.split("=", 1)[0] in _GIT_BRANCH_MUTATING for a in args) or (pos and not listing):
            return RiskClass.LOCAL_WRITE, "shell.write"
        return RiskClass.READ, "shell.read"
    if sub == "tag":
        if "-d" in args or "--delete" in args:
            return RiskClass.DELETE, "shell.delete"
        listing = "-l" in args or "--list" in args
        if (pos and not listing) or any(a in ("-a", "-s", "-f", "-m", "-u", "--force", "--annotate", "--sign") for a in args):
            return RiskClass.LOCAL_WRITE, "shell.write"
        return RiskClass.READ, "shell.read"
    if sub == "remote":
        if not pos or pos[0] in ("show", "get-url"):
            return RiskClass.READ, "shell.read"
        return RiskClass.LOCAL_WRITE, "shell.write"
    if sub == "stash":
        if pos and pos[0] in ("list", "show"):
            return RiskClass.READ, "shell.read"
        if pos and pos[0] in ("drop", "clear"):
            return RiskClass.DELETE, "shell.delete"
        return RiskClass.LOCAL_WRITE, "shell.write"
    if sub in _GIT_READ_SUBCMDS:
        if any(a == "--ext-diff" or a.startswith(("--open-files-in-pager", "-O")) for a in args):
            return RiskClass.EXECUTION, "shell.exec"
        if any(a == "--output" or a.startswith("--output=") for a in args):
            return RiskClass.LOCAL_WRITE, "shell.write"
        return RiskClass.READ, "shell.read"
    return RiskClass.EXECUTION, "shell.exec"


# ---------------------------------------------------------------------------
# Shell network destinations (for explicit "only use <domain>" bounds)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ShellNetwork:
    """Where a shell command's recognized network programs connect.

    ``verified`` is True only when every network segment's destinations were
    determined completely; ``hosts`` then lists all of them. Anything the parser
    does not understand makes the command unverified, never "no destination".
    """

    hosts: tuple[str, ...]
    verified: bool


#: Programs whose destination cannot be read from the command line: ssh-family
#: hosts may be ~/.ssh/config aliases, mail tools name recipients, not hosts.
_NETWORK_UNPARSED = frozenset({"ssh", "scp", "sftp", "rsync", "ftp", "mail", "sendmail", "mutt"})
_NETWORK_PROGRAMS = frozenset({"curl", "wget", "http", "https", "xh", "nc", "ncat", "netcat", "telnet", "git"}) | _NETWORK_UNPARSED
#: git subcommands that contact a remote; remotes are names or URLs git resolves itself.
_GIT_NETWORK_SUBCMDS = frozenset({"push", "send-email", "request-pull", "fetch", "pull", "clone", "ls-remote", "submodule", "archive"})
#: Programs that run another program given as an argument (``timeout 5 curl …``).
_WRAPPERS = frozenset({"sudo", "doas", "env", "timeout", "nice", "nohup", "time", "command", "exec", "xargs", "stdbuf",
                       "ionice", "chrt", "taskset", "caffeinate", "unbuffer", "torsocks", "proxychains", "proxychains4"})
_SEGMENT_EXPANSION = re.compile(r"[$`(){}\\]")
_REDIRECT = re.compile(r"^\d*(?:>>?|<)(?:&\d*)?$")
_REDIRECT_ATTACHED = re.compile(r"^\d*(?:>>?|<)\S")
_PORT = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"})


@dataclass(frozen=True)
class _Syntax:
    """Option syntax for one network program.

    ``closed`` programs accept only the options listed: an unknown option makes the
    destination unverifiable, because a value it takes would shift which token is the
    URL, or it may route the connection. Listing a flag as value-taking would skip a
    URL, so value options come from the program's own help output.
    """

    long_values: frozenset[str] = frozenset()
    short_values: str = ""
    #: Options that proxy, remap, or read destinations from elsewhere.
    long_hidden: frozenset[str] = frozenset()
    short_hidden: str = ""
    closed: bool = False
    long_flags: frozenset[str] = frozenset()
    short_flags: str = ""
    #: GNU getopt_long: a unique prefix names an option (wget --inp = --input-file).
    abbreviations: bool = False
    #: ``--name=value``; curl rejects it as an unknown option.
    equals: bool = True
    #: curl --expand-<option>: the option's value with {{variables}} expanded.
    expand: bool = False

    def resolve(self, name: str) -> str | None:
        """The option a long name selects, or None when it selects none with certainty."""
        known = self.long_values | self.long_hidden | self.long_flags | {"--url"}
        if name in known:
            return name
        if name.startswith("--no-") and "--" + name[5:] in self.long_flags:
            return "--" + name[5:]  # a negated boolean
        if self.abbreviations:
            matches = [k for k in known if k.startswith(name)]
            if len(matches) == 1:
                return matches[0]
        return None


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# From `curl --help all` (curl 8.7.1). Routing and indirection options are hidden.
_CURL_HIDDEN = frozenset({
    "--config", "--connect-to", "--resolve", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5",
    "--socks5-hostname", "--proxy1.0", "--doh-url", "--dns-servers", "--unix-socket", "--abstract-unix-socket",
    "--mail-rcpt", "--variable", "--ftp-port", "--alt-svc", "--ipfs-gateway",
})
_CURL = _Syntax(
    long_values=_words("""
        --aws-sigv4 --cacert --capath --cert --cert-type --ciphers --connect-timeout --continue-at --cookie
        --cookie-jar --create-file-mode --crlfile --curves --data --data-ascii --data-binary --data-raw
        --data-urlencode --delegation --dns-interface --dns-ipv4-addr --dns-ipv6-addr --dump-header --egd-file
        --engine --etag-compare --etag-save --expect100-timeout --form --form-string --ftp-account
        --ftp-alternative-to-user --ftp-method --ftp-ssl-ccc-mode --happy-eyeballs-timeout-ms --haproxy-clientip
        --header --help --hostpubmd5 --hostpubsha256 --hsts --interface --json --keepalive-time --key --key-type
        --krb --libcurl --limit-rate --local-port --login-options --mail-auth --mail-from --max-filesize
        --max-redirs --max-time --netrc-file --noproxy --oauth2-bearer --output --output-dir --parallel-max --pass
        --pinnedpubkey --proto --proto-default --proto-redir --proxy-cacert --proxy-capath --proxy-cert
        --proxy-cert-type --proxy-ciphers --proxy-crlfile --proxy-header --proxy-key --proxy-key-type --proxy-pass
        --proxy-pinnedpubkey --proxy-service-name --proxy-tls13-ciphers --proxy-tlsauthtype --proxy-tlspassword
        --proxy-tlsuser --proxy-user --pubkey --quote --random-file --range --rate --referer --request
        --request-target --retry --retry-delay --retry-max-time --sasl-authzid --service-name
        --socks5-gssapi-service --speed-limit --speed-time --stderr --telnet-option --tftp-blksize --time-cond
        --tls-max --tls13-ciphers --tlsauthtype --tlspassword --tlsuser --trace --trace-ascii --trace-config
        --upload-file --url-query --user --user-agent --write-out
    """),
    long_flags=_words("""
        --anyauth --append --basic --ca-native --cert-status --compressed --compressed-ssh --create-dirs --crlf
        --digest --disable --disable-eprt --disable-epsv --disallow-username-in-url --doh-cert-status
        --doh-insecure --fail --fail-early --fail-with-body --false-start --form-escape --ftp-create-dirs
        --ftp-pasv --ftp-pret --ftp-skip-pasv-ip --ftp-ssl-ccc --ftp-ssl-control --get --globoff
        --haproxy-protocol --head --http0.9 --http1.0 --http1.1 --http2 --http2-prior-knowledge --http3
        --http3-only --ignore-content-length --include --insecure --ipv4 --ipv6 --junk-session-cookies
        --list-only --location --location-trusted --mail-rcpt-allowfails --manual --metalink --negotiate --netrc
        --netrc-optional --next --no-alpn --no-buffer --no-clobber --no-keepalive --no-npn --no-progress-meter
        --no-sessionid --ntlm --ntlm-wb --parallel --parallel-immediate --path-as-is --post301 --post302
        --post303 --progress-bar --proxy-anyauth --proxy-basic --proxy-ca-native --proxy-digest --proxy-http2
        --proxy-insecure --proxy-negotiate --proxy-ntlm --proxy-ssl-allow-beast --proxy-ssl-auto-client-cert
        --proxy-tlsv1 --proxytunnel --raw --remote-header-name --remote-name --remote-name-all --remote-time
        --remove-on-error --retry-all-errors --retry-connrefused --sasl-ir --show-error --silent --socks5-basic
        --socks5-gssapi --socks5-gssapi-nec --ssl --ssl-allow-beast --ssl-auto-client-cert --ssl-no-revoke
        --ssl-reqd --ssl-revoke-best-effort --sslv2 --sslv3 --styled-output --suppress-connect-headers
        --tcp-fastopen --tcp-nodelay --tftp-no-options --tlsv1 --tlsv1.0 --tlsv1.1 --tlsv1.2 --tlsv1.3
        --tr-encoding --trace-ids --trace-time --use-ascii --verbose --version --xattr
    """),
    short_values="ACDEFHQTUXYbcdehmortuwyz",
    short_flags="#012346:BGIJLMNORSVZafgijklnpqsv",
    long_hidden=_CURL_HIDDEN,
    short_hidden="KPx",
    closed=True, equals=False, expand=True,
)
# GNU wget 1.21 (`wget --help`). getopt_long accepts --name=value and unique prefixes.
_WGET = _Syntax(
    long_values=_words("""
        --output-file --append-output --report-speed --rejected-log --tries --retry-on-http-error
        --output-document --start-pos --progress --timeout --bind-dns-address --dns-timeout --connect-timeout
        --read-timeout --wait --waitretry --quota --limit-rate --restrict-file-names --prefer-family --user
        --password --local-encoding --remote-encoding --directory-prefix --cut-dirs --http-user --http-password
        --default-page --header --compression --max-redirect --proxy-user --proxy-password --referer --user-agent
        --load-cookies --save-cookies --post-data --post-file --method --body-data --body-file --secure-protocol
        --certificate --certificate-type --private-key --private-key-type --ca-certificate --ca-directory
        --crl-file --pinnedpubkey --random-file --egd-file --ciphers --hsts-file --ftp-user --ftp-password
        --warc-file --warc-header --warc-max-size --warc-dedup --warc-tempdir --level --backups --accept --reject
        --accept-regex --reject-regex --regex-type --domains --exclude-domains --follow-tags --ignore-tags
        --include-directories --exclude-directories --metalink-index --preferred-location
    """),
    long_flags=_words("""
        --version --help --background --debug --quiet --verbose --no-verbose --force-html --no-config
        --retry-connrefused --retry-on-host-error --no-clobber --no-netrc --continue --show-progress --timestamping
        --no-if-modified-since --no-use-server-timestamps --server-response --spider --random-wait --no-proxy
        --no-dns-cache --ignore-case --inet4-only --inet6-only --ask-password --no-iri --unlink --xattr
        --no-directories --force-directories --no-host-directories --protocol-directories --no-cache
        --adjust-extension --html-extension --ignore-length --save-headers --no-http-keep-alive --no-cookies
        --keep-session-cookies --content-disposition --content-on-error --auth-no-challenge --https-only
        --no-check-certificate --no-hsts --no-remove-listing --no-glob --no-passive-ftp --preserve-permissions
        --retr-symlinks --ftps-implicit --ftps-resume-ssl --ftps-clear-data-connection --ftps-fallback-to-ftp
        --warc-cdx --no-warc-compression --no-warc-digests --no-warc-keep-log --recursive --delete-after
        --convert-links --convert-file-only --backup-converted --mirror --page-requisites --strict-comments
        --follow-ftp --relative --no-parent --trust-server-names
    """),
    short_values="OoaPUtTwQlARDIXn",
    short_flags="VhbdqvFcNSxErkKmpL46",
    long_hidden=frozenset({"--input-file", "--base", "--execute", "--config", "--span-hosts", "--input-metalink",
                           "--metalink-over-http", "--bind-address", "--use-askpass", "--dns-servers"}),
    short_hidden="iBeH",
    closed=True, abbreviations=True,
)
_HTTPIE = _Syntax(
    long_values=frozenset({
        "--auth", "--auth-type", "--output", "--session", "--session-read-only", "--verify", "--cert", "--cert-key",
        "--cert-key-pass", "--ssl", "--ciphers", "--timeout", "--max-redirects", "--pretty", "--style", "--print",
        "--history-print", "--format-options", "--response-charset", "--response-mime", "--boundary", "--max-headers",
        "--bearer", "--http-version", "--raw", "--default-scheme", "--interface",
    }),
    short_values="aAospP",
    long_hidden=frozenset({"--proxy", "--resolve", "--unix-socket"}),
    closed=True,
    long_flags=frozenset({
        "--verbose", "--headers", "--body", "--meta", "--form", "--json", "--follow", "--download", "--continue",
        "--ignore-stdin", "--quiet", "--offline", "--check-status", "--compress", "--multipart", "--all", "--stream",
        "--chunked", "--path-as-is", "--ignore-netrc", "--sorted", "--unsorted", "--debug", "--traceback", "--https",
        "--native-tls", "--no-follow",
    }),
    short_flags="vhbmjfFdcIqxS46",
)
_NC = _Syntax(short_values="IiMmOPpqsTVwXec", short_hidden="xlU")
_TELNET = _Syntax(short_values="elnbSX")


def _dest_tokens(argv: list[str], syntax: _Syntax) -> list[str] | None:
    """Positional arguments after options and redirections; None when the destination is hidden."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        i += 1
        if _REDIRECT.match(tok):
            i += 1  # its target
            continue
        if _REDIRECT_ATTACHED.match(tok):
            continue
        if tok == "--":
            out.extend(argv[i:])
            break
        if tok.startswith("--"):
            raw, eq, attached = tok.partition("=")
            if eq and not syntax.equals:
                return None
            expanded = syntax.expand and raw.startswith("--expand-")
            name = syntax.resolve("--" + raw[len("--expand-"):] if expanded else raw)
            if name is None:
                if syntax.closed:
                    return None
                continue  # an open syntax reads an unknown option as a flag
            if name in syntax.long_hidden:
                return None
            takes_value = name in syntax.long_values or name == "--url"
            if expanded and (name == "--url" or not takes_value):
                return None  # an expanded destination cannot be read; only value options expand
            if name == "--url":  # curl: the value is a destination
                if eq:
                    out.append(attached)
                elif i < len(argv):
                    out.append(argv[i])
                    i += 1
                else:
                    return None
                continue
            if takes_value and not eq:
                i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            letters = tok[1:]
            for k, ch in enumerate(letters):
                if ch in syntax.short_hidden:
                    return None
                if ch in syntax.short_values:
                    if k == len(letters) - 1:
                        i += 1  # separate value
                    break  # the rest of the cluster is the value
                if syntax.closed and ch not in syntax.short_flags:
                    return None
            continue
        out.append(tok)
    return out


_AUTHORITY = re.compile(r"^(?:[^@\s/]+@)?(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._~-]+)(?::\d{1,5})?$")


def _host(token: str, *, default_localhost: bool = False) -> str | None:
    """The host a URL or bare host names, or None when it cannot be read with certainty.

    Strict on purpose: ``example.com:443:attacker.example:443`` (a curl --connect-to value)
    is not a host, and neither is anything with percent-encoding or a second port.
    """
    text = unicodedata.normalize("NFKC", token).strip()
    if default_localhost and text.startswith(":"):
        text = "localhost" + text
    authority = text.split("://", 1)[1] if "://" in text else text
    authority = re.split(r"[/?#]", authority, maxsplit=1)[0]
    if not authority or not _AUTHORITY.match(authority):
        return None  # includes several "@": parsers disagree about which one ends the user info
    host = domain_of(text if "://" in text else "http://" + text)
    return host if host and re.fullmatch(r"[\w.\-:\[\]]+", host) else None


def _segment_network(argv: list[str]) -> tuple[list[str], bool] | None:
    """``(hosts, verified)`` for one segment's argv, or None when it runs no recognized network program."""
    prefixed = False
    while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
        argv, prefixed = argv[1:], True  # e.g. https_proxy=… sends the request elsewhere
    if not argv:
        return None
    if "/" in argv[0] and not _system_program(argv[0]):
        return None  # an arbitrary program: execution, not a recognized network call
    prog, rest = Path(argv[0]).name, argv[1:]
    if prog in _WRAPPERS:
        wrapped = any(Path(a).name in _NETWORK_PROGRAMS for a in rest)
        return ([], False) if wrapped else None
    if prog not in _NETWORK_PROGRAMS:
        return None
    if prog == "git":
        split = _git_split(rest)
        if split is None:
            return ([], False) if any(a in _GIT_NETWORK_SUBCMDS for a in rest) else None
        sub, args = split
        pos = _positional(args)
        remote = sub == "remote" and bool(pos) and pos[0] in ("show", "update", "prune")
        return ([], False) if sub in _GIT_NETWORK_SUBCMDS or remote else None
    if prefixed or prog in _NETWORK_UNPARSED:
        return [], False
    if prog == "curl":
        tokens = _dest_tokens(rest, _CURL)
        if not tokens:
            return [], False
        hosts = [_host(t) for t in tokens]
    elif prog == "wget":
        tokens = _dest_tokens(rest, _WGET)
        if not tokens:
            return [], False
        hosts = [_host(t) for t in tokens]
    elif prog in ("http", "https", "xh"):
        tokens = _dest_tokens(rest, _HTTPIE)
        if not tokens:
            return [], False
        if tokens[0].upper() in _HTTP_METHODS and len(tokens) > 1:
            tokens = tokens[1:]
        items = tokens[1:]
        # Request items are header:value, field=value, field==value, field:=json, field@file.
        if any(not re.search(r"[:=@]", item) for item in items):
            return [], False
        hosts = [_host(tokens[0], default_localhost=True)]
    else:  # nc, ncat, netcat, telnet: host, then ports
        tokens = _dest_tokens(rest, _TELNET if prog == "telnet" else _NC)
        if not tokens or any(t.startswith("--") for t in rest) or not all(_PORT.match(t) for t in tokens[1:]):
            return [], False
        hosts = [_host(tokens[0])]
    if any(h is None for h in hosts):
        return [h for h in hosts if h], False
    return [h for h in hosts if h], True


def shell_network(command: str) -> ShellNetwork | None:
    """Destinations of every recognized network program in ``command``; None when it runs none.

    Segments are split exactly as :func:`classify_shell` splits them. A network
    segment with shell expansion, unparseable quoting, a hidden destination or
    no destination at all makes the whole command unverified.
    """
    cmd = (command or "").strip()
    hosts: list[str] = []
    verified, found = True, False
    names = "|".join(re.escape(n) for n in sorted(_NETWORK_PROGRAMS | _WRAPPERS))
    for segment in (s.strip() for s in re.split(r"\|\||&&|[|;\n&]", cmd)):
        if not segment:
            continue
        try:
            argv = shlex.split(segment)
        except ValueError:
            if re.search(rf"(?<![\w.-])(?:{names})(?![\w.-])", segment):
                found, verified = True, False
            continue
        result = _segment_network(argv)
        if result is None:
            continue
        found = True
        seg_hosts, seg_ok = result
        if not seg_ok or _SEGMENT_EXPANSION.search(segment):
            verified = False
        hosts.extend(h for h in seg_hosts if h not in hosts)
    if not found:
        return None
    return ShellNetwork(tuple(hosts), verified)


# ---------------------------------------------------------------------------
# Patch text (V4A multi-file patches and unified diffs)
# ---------------------------------------------------------------------------

# Mirrors hermes tools/patch_parser.py (``re.match`` per line), made case-insensitive
# and whitespace-tolerant so that anything Hermes accepts is also seen here.
_V4A_FILE = re.compile(r"^\*\*\*\s*(Add|Update|Delete)\s+File\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_V4A_MOVE_FILE = re.compile(r"^\*\*\*\s*Move\s+File\s*:\s*(.+?)\s*->\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_V4A_MOVE = re.compile(r"^\*\*\*\s*Move\s+to\s*:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_UDIFF_FILE = re.compile(r"^(---|\+\+\+) (?:[ab]/)?([^\t\n]+?)(?:\t.*)?$", re.MULTILINE)
_GIT_DIFF = re.compile(r"^diff --git a/(\S+) b/(\S+)$", re.MULTILINE)


@dataclass
class PatchInfo:
    paths: list[str] = field(default_factory=list)
    deletes: bool = False
    moves: bool = False
    parsed: bool = False


def parse_patch(text: str) -> PatchInfo:
    """Files named by a V4A patch (``*** Update File: …``) or a unified diff."""
    info = PatchInfo()

    def add(p: str) -> None:
        p = p.strip()
        if p and p != "/dev/null" and p not in info.paths:
            info.paths.append(p)

    for kind, path in _V4A_FILE.findall(text or ""):
        add(path)
        info.parsed = True
        if kind.lower() == "delete":
            info.deletes = True
    for src, dst in _V4A_MOVE_FILE.findall(text or ""):
        # A move removes the source and creates the destination: both are checked.
        add(src)
        add(dst)
        info.parsed = True
        info.moves = True
    for path in _V4A_MOVE.findall(text or ""):
        add(path)
        info.parsed = True
    for a, b in _GIT_DIFF.findall(text or ""):
        add(a)
        add(b)
        info.parsed = True
    lines = _UDIFF_FILE.findall(text or "")
    for marker, path in lines:
        info.parsed = True
        if marker == "+++" and path.strip() == "/dev/null":
            info.deletes = True
        add(path)
    if "deleted file mode" in (text or ""):
        info.deletes = True
    # Inside Hermes, also ask Hermes' own parser: whatever it would apply, we check.
    host = _host_patch_parser()
    if host is not None:
        try:
            ops, _err = host(text or "")
        except Exception:
            ops = []
        for op in ops or []:
            kind = str(getattr(getattr(op, "operation", None), "value", getattr(op, "operation", ""))).lower()
            add(str(getattr(op, "file_path", "") or ""))
            if getattr(op, "new_path", None):
                add(str(op.new_path))
                info.moves = True
            info.parsed = True
            if "delete" in kind:
                info.deletes = True
    return info


def _host_patch_parser() -> Any:
    try:
        from tools.patch_parser import parse_v4a_patch

        return parse_v4a_patch
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Target extraction (recipients, domains, paths)
# ---------------------------------------------------------------------------

_ACTION_KEYS = ("action", "operation", "op", "method", "verb")

_EMAIL_IN_ANGLE = re.compile(r"<\s*([^<>\s]+@[^<>\s]+)\s*>")
_EMAIL_ANY = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
#: Argument keys that carry message *content*. Addresses or links inside these are
#: things the message talks about, not where it goes, so they are not targets.
CONTENT_KEYS = frozenset(
    {
        "body", "content", "text", "message", "subject", "html", "markdown", "description", "note", "notes",
        "comment", "summary", "title", "snippet", "caption", "prompt", "query", "q", "code", "old_string",
        "new_string", "patch", "file_content", "data", "payload_text",
    }
)


def normalize_recipient(value: str) -> str:
    """Normalize a recipient for exact comparison.

    NFKC folds full-width and compatibility characters; ``Name <a@b>`` keeps
    only the address; ``mailto:`` is stripped. Homoglyphs that survive NFKC
    (e.g. Cyrillic ``а``) are *kept*, so they never match an ASCII allowlist
    entry.
    """
    text = unicodedata.normalize("NFKC", value).strip()
    m = _EMAIL_IN_ANGLE.search(text)
    if m:
        text = m.group(1)
    if text.lower().startswith("mailto:"):
        text = text[7:]
    return text.strip().strip(".,;").lower()


def domain_of(value: str) -> str | None:
    text = unicodedata.normalize("NFKC", value).strip()
    if "@" in text and "://" not in text:
        return text.rsplit("@", 1)[1].strip(" >").lower() or None
    if "://" not in text:
        text = "http://" + text
    try:
        host = urlsplit(text).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def domain_matches(host: str, allowed: Iterable[str]) -> bool:
    """Exact host or a dot-boundary subdomain of an allowed domain."""
    host = host.lower().rstrip(".")
    for entry in allowed:
        entry = entry.lower().lstrip("*.").rstrip(".")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def normalize_path(value: str, cwd: Path | None = None) -> str:
    p = Path(unicodedata.normalize("NFKC", value).strip()).expanduser()
    if not p.is_absolute():
        p = (cwd or Path.cwd()) / p
    try:
        return str(p.resolve(strict=False))
    except (OSError, RuntimeError):
        return str(p)


def path_within(path: str, roots: Iterable[str]) -> bool:
    for root in roots:
        r = normalize_path(root)
        if path == r or path.startswith(r.rstrip("/") + "/"):
            return True
    return False


def _split_multi(value: str) -> list[str]:
    return [p for p in re.split(r"[,;\n]+", value) if p.strip()]


def _collect_strings(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(_collect_strings(v))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            out.extend(_collect_strings(v))
    elif value is not None:
        out.append(str(value))
    return out


def _walk_non_content(args: Any, skip: set[str]) -> list[str]:
    """Every string in ``args`` except those under content keys or ``skip`` keys."""
    found: list[str] = []
    if isinstance(args, dict):
        for k, v in args.items():
            kl = k.lower() if isinstance(k, str) else ""
            if kl in CONTENT_KEYS or kl in skip:
                continue
            found.extend(_walk_non_content(v, skip))
    elif isinstance(args, (list, tuple)):
        for v in args:
            found.extend(_walk_non_content(v, skip))
    elif isinstance(args, str):
        found.append(args)
    return found


def _walk_keys(args: Any, keys: set[str]) -> list[str]:
    """Collect every string under any (case-insensitive) matching key, at any depth."""
    found: list[str] = []
    if isinstance(args, dict):
        for k, v in args.items():
            if isinstance(k, str) and k.lower() in keys:
                found.extend(_collect_strings(v))
            else:
                found.extend(_walk_keys(v, keys))
    elif isinstance(args, (list, tuple)):
        for v in args:
            found.extend(_walk_keys(v, keys))
    return found


@dataclass
class Targets:
    recipients: list[str] = field(default_factory=list)
    #: Hosts of URLs found in the arguments (recipient domains are not included).
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    command: str | None = None
    #: Patch text was supplied but named no files we could parse: paths are unknown.
    unverified_paths: bool = False
    #: The call asked to write into another Hermes profile.
    cross_profile: bool = False
    #: Destinations of the network programs a shell command runs (None: it runs none).
    network: ShellNetwork | None = None


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class RiskClassifier:
    def __init__(self, risk_config: dict[str, Any]):
        self.tools: dict[str, dict[str, Any]] = risk_config.get("tools") or {}
        self.patterns: list[dict[str, Any]] = risk_config.get("patterns") or []
        self.domains: dict[str, list[str]] = risk_config.get("domains") or {}
        self.verbs: dict[RiskClass, set[str]] = {
            RiskClass(k): {v.lower() for v in vs} for k, vs in (risk_config.get("verbs") or {}).items()
        }
        self.strong: dict[RiskClass, set[str]] = {
            RiskClass(k): {v.lower() for v in vs} for k, vs in (risk_config.get("strong_verbs") or {}).items()
        }
        hints = risk_config.get("arg_hints") or {}
        self.recipient_hints = tuple(h.lower() for h in hints.get("recipient", []))
        self.domain_hints = tuple(h.lower() for h in hints.get("domain", []))
        self.path_hints = tuple(h.lower() for h in hints.get("path", []))
        # Verb lookup preserving the configured priority order.
        self._verb_order: list[tuple[str, RiskClass]] = []
        for risk, words in (risk_config.get("verbs") or {}).items():
            for w in words:
                self._verb_order.append((w.lower(), RiskClass(risk)))

    # -- public ------------------------------------------------------------

    def classify(self, tool_name: str, args: dict[str, Any] | None = None) -> ToolProfile:
        args = args or {}
        spec = self.tools.get(tool_name)
        if spec is not None:
            return self._action_net(self._from_spec(tool_name, spec, args, source="mapped"), spec, args)
        for pat in self.patterns:
            if fnmatch.fnmatchcase(tool_name, pat.get("match", "")):
                if pat.get("risk") == "infer":
                    return self._action_net(self.infer(tool_name), {}, args)
                return self._action_net(self._from_spec(tool_name, pat, args, source="pattern"), pat, args)
        return self._action_net(self.infer(tool_name), {}, args)

    def _action_net(self, profile: ToolProfile, spec: dict[str, Any], args: dict[str, Any]) -> ToolProfile:
        """A tool that classifies as READ but was given an action it doesn't list
        is never trusted as a read.

        Many tools multiplex reads and writes behind an ``action`` argument
        (``spotify_library(action="remove")``). Explicit ``arg_risk`` rules handle
        known actions. For anything else the action's own verb decides
        ("remove" → DELETE), and an action with no recognizable verb is UNKNOWN.
        """
        if profile.risk is not RiskClass.READ:
            return profile
        declared = {str(a) for a in (spec.get("read_actions") or [])}
        for rule in (spec.get("arg_risk") or {}).values():
            declared |= {str(k) for k, v in rule.items() if str(v) == RiskClass.READ.value}
        for key in _ACTION_KEYS:
            value = args.get(key)
            if not isinstance(value, str) or not value.strip() or value in declared:
                continue
            tokens = tokenize(value)
            verb_index = {w: r for w, r in reversed(self._verb_order)}
            risk = next((verb_index[t] for t in tokens if t in verb_index), RiskClass.UNKNOWN)
            for strong_risk in _STRONG_ORDER:
                if set(tokens) & self.strong.get(strong_risk, set()):
                    risk = strong_risk
                    break
            if risk is RiskClass.READ:
                continue
            return profile.model_copy(
                update={"risk": risk, "capability": f"{profile.capability.split('.', 1)[0]}.{_ACTION_NAMES[risk]}", "source": "inferred" if risk is not RiskClass.UNKNOWN else "unknown"}
            )
        return profile

    def proven_read_only(self, capability: str) -> bool:
        """True only if every configured mapping to this capability is a plain read.

        Conservative on purpose: unknown capabilities, tool names, globs, names that
        verb inference can also produce, and any mapping whose risk depends on its
        arguments (a tool that multiplexes reads and writes) are not proven.
        """
        name = capability.strip().lower()
        if not name or "." not in name or any(ch in name for ch in "*?[") or name in {t.lower() for t in self.tools}:
            return False
        inferable = {f"{domain}.{action}" for domain in [*self.domains, "mcp", "tool"] for action in _ACTION_NAMES.values()}
        if name in inferable:
            return False
        specs = [spec for spec in self.tools.values() if str(spec.get("capability") or "").lower() == name]
        specs += [pat for pat in self.patterns if str(pat.get("capability") or "").lower() == name]
        multi_operation = ("arg_risk", "arg_present_risk", "action_args", "patch_args", "read_actions")
        return bool(specs) and all(str(spec.get("risk")) == RiskClass.READ.value and not any(spec.get(k) for k in multi_operation)
                                   for spec in specs)

    def capability_risk(self, capability: str) -> RiskClass:
        """The risk of a policy capability entry: its configured mappings when they agree, else inference.

        Verb inference alone reads ``file.write`` as an external write; the tools
        configured under that capability (``write_file``, ``patch``) are local writes.
        """
        name = capability.strip().lower()
        risks = {str(spec.get("risk")) for spec in [*self.tools.values(), *self.patterns]
                 if str(spec.get("capability") or "").lower() == name}
        if len(risks) == 1 and (only := risks.pop()) in RiskClass.__members__:
            return RiskClass(only)
        return self.infer(name.replace(".", "_")).risk

    def capability_has_targets(self, capability: str) -> bool:
        """Whether calls under this capability name a site (a mapped tool has domain arguments)."""
        name = capability.strip().lower()
        return any(spec.get("domain_args") for spec in [*self.tools.values(), *self.patterns]
                   if str(spec.get("capability") or "").lower() == name)

    def infer(self, tool_name: str) -> ToolProfile:
        tokens = tokenize(tool_name)
        is_mcp = bool(tokens) and tokens[0] == "mcp"
        if is_mcp:
            tokens = tokens[1:]
        risk = RiskClass.UNKNOWN
        verb_index = {w: r for w, r in reversed(self._verb_order)}  # first listed wins on dupes
        for tok in tokens:
            if tok in verb_index:
                risk = verb_index[tok]
                break
        token_set = set(tokens)
        for strong_risk in _STRONG_ORDER:
            if token_set & self.strong.get(strong_risk, set()):
                if _rank(strong_risk) > _rank(risk) or risk in (RiskClass.UNKNOWN, RiskClass.READ):
                    risk = strong_risk
                break
        domain = self._domain_for(tokens, default="mcp" if is_mcp else "tool")
        capability = f"{domain}.{_ACTION_NAMES[risk]}"
        return ToolProfile(
            tool_name=tool_name,
            capability=capability,
            risk=risk,
            source="unknown" if risk is RiskClass.UNKNOWN else "inferred",
            recipient_args=self.recipient_hints,
            domain_args=self.domain_hints,
            path_args=self.path_hints,
        )

    def extract_targets(self, profile: ToolProfile, args: dict[str, Any] | None) -> Targets:
        args = args or {}
        t = Targets()
        recipient_keys = {k.lower() for k in profile.recipient_args}
        if profile.risk in (RiskClass.COMMUNICATION, RiskClass.PERMISSION_CHANGE, RiskClass.EXTERNAL_WRITE):
            recipient_keys |= set(self.recipient_hints)
        if recipient_keys and profile.risk is not RiskClass.READ:
            for raw in _walk_keys(args, recipient_keys):
                for part in _split_multi(raw):
                    norm = normalize_recipient(part)
                    if norm and norm not in t.recipients:
                        t.recipients.append(norm)
        if profile.risk in (RiskClass.COMMUNICATION, RiskClass.PERMISSION_CHANGE, RiskClass.EXTERNAL_WRITE):
            # Addresses under keys we don't recognise (forward_to, destination, …)
            # are treated as recipients too, so they can't be smuggled past binding.
            for raw in _walk_non_content(args, recipient_keys):
                for addr in _EMAIL_ANY.findall(raw):
                    norm = normalize_recipient(addr)
                    if norm and norm not in t.recipients:
                        t.recipients.append(norm)
        domain_keys = {k.lower() for k in profile.domain_args} | set(self.domain_hints)
        urls = _walk_keys(args, domain_keys)
        command = args.get("command") if isinstance(args.get("command"), str) else None
        if command:
            t.command = command
            urls.extend(URL_RE.findall(command))
            if profile.capability.startswith("shell."):
                t.network = shell_network(command)
        # A URL under any non-content key counts (``page=``, ``target=``, nested fields).
        for s in _walk_non_content(args, domain_keys | {"command"}):
            urls.extend(URL_RE.findall(s))
        for u in urls:
            for part in _split_multi(u) if not u.startswith("http") else [u]:
                d = domain_of(part)
                if d:
                    if part not in t.urls:
                        t.urls.append(part.strip())
                    if d not in t.domains:
                        t.domains.append(d)
        path_keys = {k.lower() for k in profile.path_args} | set(self.path_hints)
        cwd = Path(str(args.get("workdir"))) if args.get("workdir") else None
        for raw in _walk_keys(args, path_keys):
            if raw and not URL_RE.match(raw):
                np = normalize_path(raw, cwd)
                if np not in t.paths:
                    t.paths.append(np)
        # Multi-file patches name their files inside the patch text.
        for key in profile.patch_args:
            text = args.get(key)
            if isinstance(text, str) and text.strip():
                info = parse_patch(text)
                if not info.parsed:
                    t.unverified_paths = True
                for raw in info.paths:
                    np = normalize_path(raw, cwd)
                    if np not in t.paths:
                        t.paths.append(np)
        t.cross_profile = bool(args.get("cross_profile"))
        return t

    # -- internals ---------------------------------------------------------

    def _from_spec(self, tool_name: str, spec: dict[str, Any], args: dict[str, Any], *, source: str) -> ToolProfile:
        risk = RiskClass(spec.get("risk", "UNKNOWN"))
        capability = spec.get("capability") or f"tool.{tool_name}"
        for arg_name, mapping in (spec.get("arg_risk") or {}).items():
            value = args.get(arg_name)
            if isinstance(value, str) and value in mapping:
                risk = RiskClass(mapping[value])
                # e.g. send_message(action="list") is message.read, not message.send
                capability = f"{capability.split('.', 1)[0]}.{_ACTION_NAMES[risk]}"
                break
        # An argument whose mere presence changes what the tool does, e.g.
        # browser_console(expression=...) runs JavaScript in the page.
        for arg_name, target in (spec.get("arg_present_risk") or {}).items():
            if args.get(arg_name) not in (None, "", [], {}, False):
                new = RiskClass(target)
                if _rank(new) > _rank(risk) or risk is RiskClass.READ:
                    risk = new
                    capability = f"{capability.split('.', 1)[0]}.{_ACTION_NAMES[risk]}"
        patch_args = tuple(spec.get("patch_args") or ())
        for key in patch_args:
            text = args.get(key)
            if isinstance(text, str) and parse_patch(text).deletes and _rank(RiskClass.DELETE) > _rank(risk):
                risk = RiskClass.DELETE
                capability = f"{capability.split('.', 1)[0]}.delete"
        if tool_name == "terminal":
            risk, capability = classify_shell(str(args.get("command", "")))
        return ToolProfile(
            tool_name=tool_name,
            capability=capability,
            risk=risk,
            source=source,  # type: ignore[arg-type]
            recipient_args=tuple(spec.get("recipient_args") or ()),
            domain_args=tuple(spec.get("domain_args") or ()),
            path_args=tuple(spec.get("path_args") or ()),
            patch_args=patch_args,
            action_args=tuple(spec.get("action_args") or ()),
        )

    def _domain_for(self, tokens: list[str], default: str) -> str:
        for domain, keywords in self.domains.items():
            kw = {k.lower() for k in keywords}
            if any(t in kw for t in tokens):
                return domain
        return default


# ---------------------------------------------------------------------------
# Action fingerprint (binds approvals to one exact action)
# ---------------------------------------------------------------------------


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFKC", value).strip()
    return value


def action_fingerprint(profile: ToolProfile, args: dict[str, Any] | None, targets: Targets) -> tuple[str, str]:
    """Return ``(digest, description)`` for the action a call performs.

    Tools with a declared ``action_args`` (``terminal.command``,
    ``execute_code.code``, ``browser_console.expression``) are fingerprinted on
    exactly those arguments. Other tools use every argument except message
    content (body, subject, file content, ...), plus the extracted recipients,
    domains and paths. Content is excluded on purpose: approving "send to John"
    covers another message to John, not a message to anyone else.
    """
    args = args or {}
    if profile.action_args:
        material: dict[str, Any] = {k: args.get(k) for k in profile.action_args}
    else:
        material = {k: v for k, v in args.items() if not (isinstance(k, str) and k.lower() in CONTENT_KEYS)}
    material["__tool"] = profile.tool_name
    material["__capability"] = profile.capability
    material["__risk"] = profile.risk.value
    material["__recipients"] = sorted(targets.recipients)
    material["__domains"] = sorted(targets.domains)
    material["__paths"] = sorted(targets.paths)
    if targets.unverified_paths:
        # Opaque patch: only this exact text is approved.
        material["__raw"] = args
    digest = hashlib.sha256(json.dumps(_canonical(material), sort_keys=True, default=str).encode()).hexdigest()[:24]
    desc_parts: list[str] = []
    for k in profile.action_args:
        v = args.get(k)
        if isinstance(v, str) and v:
            desc_parts.append(v if len(v) <= 160 else v[:157] + "…")
    if targets.recipients:
        desc_parts.append("to " + ", ".join(targets.recipients))
    if targets.paths:
        desc_parts.append("on " + ", ".join(targets.paths[:4]))
    if targets.domains and not desc_parts:
        desc_parts.append("at " + ", ".join(targets.domains))
    return digest, "; ".join(desc_parts) or profile.tool_name
