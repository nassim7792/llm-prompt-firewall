"""Command line interface.

    promptfw inspect [--trust data|user] [--policy FILE] [TEXT]     # stdin if TEXT is omitted
    promptfw egress  [--canary SECRET ...] [--allow-host HOST ...] [TEXT]
    promptfw demo                                                    # library walkthrough, offline
    promptfw bench   [--explain] [--no-ablation]
    promptfw proxy   [--host 127.0.0.1] [--port 8080] [--upstream URL] [--policy FILE]
    promptfw fuzz    [--n 300] [--seed 0] [--candidates DIR]
    promptfw token   USER [--role R]... [--ttl S] [--confirm TOOL ARGS_JSON]...

Exit status: 0 when allowed, 1 when blocked, so it composes in shell pipelines.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace

from promptfw.context import Context, Origin
from promptfw.firewall import Firewall
from promptfw.policy import Policy
from promptfw.tools import AgentReply


def _policy(path: str | None) -> Policy:
    return Policy.load(path) if path else Policy()


def _text(arg: str | None) -> str:
    return arg if arg is not None else sys.stdin.read()


def _emit(verdict, as_json: bool) -> int:
    print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False) if as_json else verdict.summary())
    return 1 if verdict.blocked else 0


def cmd_inspect(a: argparse.Namespace) -> int:
    text = _text(a.text)
    ctx = Context().system("You are a helpful assistant.")
    ctx = ctx.data(text, Origin(a.origin.split(":")[0], a.origin.partition(":")[2] or "cli")) if a.trust == "data" \
        else ctx.user(text)
    return _emit(Firewall(_policy(a.policy)).inspect(ctx), a.json)


def cmd_egress(a: argparse.Namespace) -> int:
    p = _policy(a.policy)
    p = replace(p, canaries=(*p.canaries, *a.canary), allowed_hosts=(*p.allowed_hosts, *a.allow_host))
    return _emit(Firewall(p).inspect_egress(AgentReply(_text(a.text)), Context()), a.json)


def cmd_demo(_: argparse.Namespace) -> int:
    from promptfw.demo import main as demo_main
    demo_main()
    return 0


def cmd_bench(a: argparse.Namespace) -> int:
    from promptfw.bench import default_corpus, run
    root = default_corpus()
    policy = Policy.load(a.policy) if a.policy else Policy.load(root.parent / "policy.yaml")
    print(run(root, policy, ablation=not a.no_ablation).render(explain=a.explain))
    return 0


def cmd_proxy(a: argparse.Namespace) -> int:
    import os

    import uvicorn

    from promptfw.proxy import create_app
    key = os.getenv("PROMPTFW_PRINCIPAL_KEY")
    app = create_app(_policy(a.policy), upstream_url=a.upstream, audit_path=a.audit,
                     principal_key=key.encode() if key else None)
    uvicorn.run(app, host=a.host, port=a.port, log_level="info")
    return 0


def cmd_fuzz(a: argparse.Namespace) -> int:
    from promptfw.eval.generate import run as fuzz
    print(fuzz(Firewall(_policy(a.policy)), a.n, a.seed, a.candidates))
    return 0


def cmd_token(a: argparse.Namespace) -> int:
    """Mint a signed identity token (what the application backend would do)."""
    import os

    from promptfw.identity import mint
    key = os.getenv("PROMPTFW_PRINCIPAL_KEY")
    if not key:
        print("PROMPTFW_PRINCIPAL_KEY is not set", file=sys.stderr)
        return 2
    confirm = [(tool, json.loads(args)) for tool, args in (a.confirm or [])]
    print(mint(key.encode(), a.sub, tuple(a.role), a.ttl, confirm))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="promptfw", description="LLM prompt injection firewall")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("inspect", help="inspect a prompt before the model")
    p.add_argument("text", nargs="?")
    p.add_argument("--trust", choices=["data", "user"], default="data")
    p.add_argument("--origin", default="cli:stdin", help="channel:ref for DATA spans")
    p.add_argument("--policy")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_inspect)

    p = sub.add_parser("egress", help="inspect a model answer before the user sees it")
    p.add_argument("text", nargs="?")
    p.add_argument("--canary", action="append", default=[])
    p.add_argument("--allow-host", action="append", default=[])
    p.add_argument("--policy")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_egress)

    p = sub.add_parser("demo", help="offline walkthrough with the gullible mock agent")
    p.set_defaults(fn=cmd_demo)

    p = sub.add_parser("bench", help="run the benchmark corpus")
    p.add_argument("--explain", action="store_true")
    p.add_argument("--no-ablation", action="store_true")
    p.add_argument("--policy")
    p.set_defaults(fn=cmd_bench)

    p = sub.add_parser("proxy", help="run the OpenAI-compatible proxy")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--upstream", help="e.g. https://api.openai.com (omit to use the offline mock agent)")
    p.add_argument("--policy")
    p.add_argument("--audit", help="JSONL audit log path")
    p.set_defaults(fn=cmd_proxy)

    p = sub.add_parser("fuzz", help="generate composed ingress attacks and report what gets through")
    p.add_argument("--n", type=int, default=300)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--policy")
    p.add_argument("--candidates", help="directory where misses are written for manual review")
    p.set_defaults(fn=cmd_fuzz)

    p = sub.add_parser("token", help="mint a signed identity token (needs PROMPTFW_PRINCIPAL_KEY)")
    p.add_argument("sub", help="user id")
    p.add_argument("--role", action="append", default=[])
    p.add_argument("--ttl", type=int, default=120, help="seconds (max 300)")
    p.add_argument("--confirm", nargs=2, action="append", metavar=("TOOL", "ARGS_JSON"),
                   help="pre-approve TOOL with exactly these arguments")
    p.set_defaults(fn=cmd_token)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
