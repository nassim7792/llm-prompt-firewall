"""toolauth: INVARIANT. The model asks, the firewall answers.

The decision never reads the model's stated reason or the payload that influenced it.
A tool is refused because the context is tainted, because the user did not confirm,
because an argument is outside its allowlist, or because the action targets an account
that is not the authenticated user's: facts, not guesses.
"""

from __future__ import annotations

from promptfw.context import Context
from promptfw.policy import Policy
from promptfw.tools import AgentReply, Guard, ToolCall
from promptfw.verdict import Finding, Severity

NAME = "toolauth"


def _block(rule: str, evidence: str, message: str) -> Finding:
    return Finding(NAME, rule, Severity.CRITICAL, True, 1.0, evidence=evidence, message=message)


class ToolAuthLayer:
    name = NAME

    def inspect(self, reply: AgentReply, ctx: Context, policy: Policy) -> list[Finding]:
        # Fail closed: with no registry configured, every tool call is "unknown" and blocked.
        findings: list[Finding] = []
        for call in reply.tool_calls:
            findings.extend(self.authorize(call, ctx, policy))
        return findings

    def authorize(self, call: ToolCall, ctx: Context, policy: Policy) -> list[Finding]:
        tool = policy.tools.get(call.name)
        if tool is None:
            return [_block("tool-unknown", call.name, "Model requested a tool that is not registered")]

        out: list[Finding] = []
        forbidden = tool.effects & policy.forbidden_effects
        if forbidden:
            out.append(_block("effect-forbidden", call.name,
                              f"{call.name} has forbidden effect(s): {sorted(e.value for e in forbidden)}"))

        missing = tool.required - call.args.keys()
        if missing:
            out.append(_block("args-missing", call.name, f"missing argument(s) {sorted(missing)}"))
        unexpected = call.args.keys() - tool.args.keys()
        if unexpected:
            out.append(_block("args-unexpected", call.name, f"undeclared argument(s) {sorted(unexpected)}"))
        for key, expected in tool.args.items():
            if key in call.args and not isinstance(call.args[key], expected):
                out.append(_block("args-type", call.name, f"{key} should be {expected.__name__}"))

        if Guard.NO_UNTRUSTED_INFLUENCE in tool.guards and ctx.tainted:
            origins = ", ".join(str(o) for o in ctx.tainted_by)
            out.append(_block("tainted-action", call.name, f"{call.name} requested downstream of {origins}"))
        if Guard.USER_CONFIRMED in tool.guards and not call.user_confirmed:
            out.append(_block("unconfirmed", call.name, f"{call.name} requires user confirmation"))
        if Guard.ARGS_ALLOWLISTED in tool.guards:
            for key, allowed in tool.allowlists.items():
                if str(call.args.get(key)) not in allowed:
                    out.append(_block("arg-not-allowlisted", f"{call.name}.{key}",
                                      f"{call.name}.{key} outside its allowlist"))
        if Guard.ARGS_BOUND_TO_SESSION in tool.guards:
            out.extend(self._session_binding(call, ctx, tool.bound_args))
        return out

    @staticmethod
    def _session_binding(call: ToolCall, ctx: Context, bound_args: frozenset[str]) -> list[Finding]:
        """The object an action targets must belong to the authenticated user (anti-BOLA).

        This is the check that was missing in the Meta AI / Instagram takeovers of May 2026:
        the assistant could change the recovery e-mail of an account the requester did not own.
        The model's claim ("this is my account") is never consulted, only the session identity
        set by the application.
        """
        if ctx.principal is None:
            # Fail closed: no authenticated identity, no account-scoped action.
            return [_block("no-principal", call.name, f"{call.name} needs an authenticated session")]
        out: list[Finding] = []
        for key in sorted(bound_args):
            target = call.args.get(key)
            if target is None or not same_identity(str(target), ctx.principal):
                out.append(_block("arg-not-session-bound", f"{call.name}.{key}",
                                  f"{call.name}.{key} targets an object the authenticated user does not own"))
        return out


def same_identity(a: str, b: str) -> bool:
    """Usernames are compared the way the platform does: case-insensitive, '@' prefix ignored."""
    return a.strip().lstrip("@").casefold() == b.strip().lstrip("@").casefold()
