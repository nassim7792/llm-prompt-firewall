"""toolauth: INVARIANT. The model asks, the firewall answers.

The decision never reads the model's stated reason or the payload that influenced it.
A tool is refused because of facts, not guesses:
  * identity    : no authenticated principal, or the target object is not theirs (anti-BOLA)
  * permission  : none of the principal's roles grants the tool's permission
  * arguments   : missing, undeclared, wrong type, outside an allowlist or a value constraint
  * context     : untrusted content entered the conversation, or no user confirmation
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
            if key in call.args and not type_ok(call.args[key], expected):
                out.append(_block("args-type", call.name, f"{key} should be {expected.__name__}"))

        for key, constraint in tool.constraints.items():
            if key in call.args:
                problems = constraint.violations(call.args[key])
                if problems:
                    out.append(_block("arg-constraint", f"{call.name}.{key}",
                                      f"{call.name}.{key} violates {', '.join(problems)}"))

        if tool.permission:
            out.extend(self._permission(call, ctx, policy, tool.permission))
        if tool.requires_attributes or tool.attribute_args:
            out.extend(self._attributes(call, ctx, tool.requires_attributes, tool.attribute_args))
        if tool.allowed_origins is not None:
            outside = [o for o in ctx.tainted_by if o.channel not in tool.allowed_origins]
            if outside:
                out.append(_block("origin-not-allowed", call.name,
                                  f"{call.name} not allowed after content from {', '.join(str(o) for o in outside)}"))

        if Guard.NO_UNTRUSTED_INFLUENCE in tool.guards:
            # A context mixing a trusted and an untrusted origin is untrusted.
            untrusted = [o for o in ctx.tainted_by if not policy.is_trusted_channel(o.channel)]
            if untrusted:
                origins = ", ".join(str(o) for o in untrusted)
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
    def _permission(call: ToolCall, ctx: Context, policy: Policy, permission: str) -> list[Finding]:
        if ctx.principal is None:
            return [_block("no-principal", call.name, f"{call.name} needs an authenticated session")]
        if permission not in policy.permissions_of(ctx.principal.roles):
            return [_block("permission-denied", call.name,
                           f"{call.name} requires permission {permission!r}, not granted to the principal's roles")]
        return []

    @staticmethod
    def _attributes(call: ToolCall, ctx: Context, required: dict[str, str], bound: dict[str, str]) -> list[Finding]:
        """ABAC: the principal must carry the required attributes, and some arguments must
        equal one of its attributes (e.g. tenant_id == principal.attributes["tenant"])."""
        if ctx.principal is None:
            return [_block("no-principal", call.name, f"{call.name} needs an authenticated session")]
        attrs = ctx.principal.attributes
        out = [_block("attribute-mismatch", f"{call.name}:{k}", f"{call.name} requires attribute {k}={v}")
               for k, v in required.items() if attrs.get(k) != v]
        for arg, attr in bound.items():
            if attr not in attrs or str(call.args.get(arg)) != attrs[attr]:
                out.append(_block("attribute-mismatch", f"{call.name}.{arg}",
                                  f"{call.name}.{arg} must equal the principal attribute {attr!r}"))
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
            if target is None or not same_identity(str(target), ctx.principal.id):
                out.append(_block("arg-not-session-bound", f"{call.name}.{key}",
                                  f"{call.name}.{key} targets an object the authenticated user does not own"))
        return out


def type_ok(value: object, expected: type) -> bool:
    """Strict JSON-style typing: bool is not an int, an integer is an acceptable float."""
    if expected is bool:
        return isinstance(value, bool)
    if isinstance(value, bool):
        return False
    if expected is float:
        return isinstance(value, (int, float))
    return isinstance(value, expected)


def same_identity(a: str, b: str) -> bool:
    """Usernames are compared the way the platform does: case-insensitive, '@' prefix ignored."""
    return a.strip().lstrip("@").casefold() == b.strip().lstrip("@").casefold()
