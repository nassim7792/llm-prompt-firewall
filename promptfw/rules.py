"""Scored ingress signatures (English + French).

These are the ONLY part of the firewall that tries to read intent from text, which is
undecidable in general: a determined attacker will paraphrase around them. They exist to
raise the cost of the copy-pasted 80%, they are scored (never invariant by default), and
the benchmark reports them separately.

`weight`      : contribution when found in a USER span (multiplied by policy.user_ingress_factor)
`data_weight` : contribution when found in a DATA span (third-party content)

Weights combine per span with a noisy-OR: 1 - prod(1 - w).

OWASP Top 10 for LLM Applications 2025: LLM01 prompt injection, LLM02 sensitive information
disclosure, LLM06 excessive agency, LLM07 system prompt leakage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_F = re.IGNORECASE | re.DOTALL


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    data_weight: float
    pattern: re.Pattern
    description: str
    owasp: str = "LLM01"


def _r(p: str, flags: int = _F) -> re.Pattern:
    return re.compile(p, flags)


# Chat-template control tokens. Highest-precision rule there is: real documents never contain them.
CHAT_TEMPLATE_MARKERS = (
    "<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>", "<|endoftext|>",
    "<|eot_id|>", "<|start_header_id|>", "<|end_header_id|>", "[inst]", "[/inst]", "<<sys>>", "<</sys>>",
    "<start_of_turn>", "<end_of_turn>",
)

RULES: list[Rule] = [
    # --- Instruction override -----------------------------------------------------------
    Rule("PI-001", "instruction_override", 0.75, 0.8, _r(
        r"\b(ignore|disregard|forget|skip|override|bypass|neglect|discard)\b[\w\s,']{0,30}?"
        r"\b(previous|prior|above|earlier|preceding|initial|original|all|any|your|system|developer)\b"
        r"[\w\s']{0,20}?\b(instructions?|prompts?|directives?|guidelines|constraints|programming|rules)\b"
        r"|\b(ignore|disregard|forget)\s+(everything|all|anything)\s+(above|before|said before|previously|prior)\b"),
        "Asks the model to ignore its instructions"),
    Rule("PI-002", "instruction_override", 0.75, 0.8, _r(
        r"\b(ignore\w*|oubli\w*|ne\s+tiens?\s+(?:pas|plus)\s+compte|fai(?:s|tes)\s+abstraction)\b.{0,40}?"
        r"\b(pr[ée]c[ée]dent\w*|ci-dessus|ant[ée]rieur\w*|initia\w*|syst[èe]me|toutes|tes|vos)\b.{0,25}?"
        r"\b(instructions?|consignes?|r[èe]gles|directives?|prompt)\b"),
        "FR : demande d'ignorer les instructions"),
    Rule("PI-003", "instruction_override", 0.35, 0.45, _r(
        r"\b(new|updated|real|actual|true|revised)\s+(system\s+)?(instructions?|rules|task|objective|directives?|polic(y|ies))\s*(:|are\b|is\b)"
        r"|\bnouvelles?\s+(instructions?|consignes?|r[èe]gles)\s*:"),
        "Introduces 'new instructions'"),
    Rule("PI-004", "instruction_override", 0.2, 0.45, _r(
        r"\bfrom now on,?\s+(you|your)\b|\b[àa] partir de maintenant,?\s+(tu|vous)\b|\bd[ée]sormais,?\s+(tu|vous)\b"),
        "Redefines the model's behaviour for the rest of the conversation"),
    Rule("PI-005", "instruction_override", 0.55, 0.7, _r(
        r"\b(do not|don't|stop|no longer)\s+(follow|obey|respect|apply)\w*\s+(the|your|any|those)\s+"
        r"(instructions?|rules|guidelines|system prompt|policies)"),
        "Asks the model to stop following its rules"),

    # --- Jailbreak / role hijacking -----------------------------------------------------
    Rule("JB-001", "jailbreak", 0.75, 0.8, _r(
        r"\b(dan\s+mode|do\s+anything\s+now|developer\s+mode\s+(enabled|activated|on)|god\s+mode|"
        r"jailbr(oken|eak)\s+mode|unfiltered\s+mode|evil\s+(confidant|mode))\b"),
        "Known jailbreak persona (DAN, developer mode...)"),
    Rule("JB-002", "jailbreak", 0.65, 0.75, _r(
        r"\b(you are|you're|act as|pretend (to be|you are)|roleplay as|behave like|tu es|agis comme|fais comme si tu [ée]tais)\b"
        r".{0,50}?\b(unrestricted|uncensored|unfiltered|jailbroken|amoral|without (any )?(rules|limits|restrictions)|"
        r"sans (aucune )?(r[èe]gles?|limites?|restrictions?|filtres?|censure))"),
        "Asks the model to impersonate an unrestricted AI"),
    Rule("JB-003", "jailbreak", 0.35, 0.5, _r(
        r"\b(no|without|free (of|from)|zero|ignore)\s+(any\s+|all\s+)?(content\s+)?(restrictions|filters|censorship|"
        r"safety (guidelines|rules|filters)|ethical (guidelines|constraints)|moral constraints)\b"
        r"|\bsans\s+(aucune?\s+)?(restrictions?|filtres?|censure|limites? [ée]thiques?)\b"),
        "Requests removal of safety restrictions"),
    Rule("JB-004", "jailbreak", 0.25, 0.35, _r(
        r"\b(stay|remain) in character\b|\bnever break character\b|\bne sors jamais (de ton|du) r[ôo]le\b"),
        "Roleplay lock-in, common in jailbreak templates"),

    # --- System prompt extraction (LLM07) -----------------------------------------------
    Rule("SP-001", "prompt_extraction", 0.65, 0.75, _r(
        r"\b(reveal|show|print|display|output|repeat|tell me|give me|leak|dump|share|recite|what (is|are|was|were))\b.{0,30}?"
        r"(\byour\s+(system\s+|initial\s+|original\s+|hidden\s+|secret\s+|internal\s+)?(prompt|instructions|system message|configuration)\b"
        r"|\bthe\s+(system|initial|original|hidden|secret|internal|developer)\s+(prompt|instructions|message)\b)"),
        "Asks for the system prompt", "LLM07"),
    Rule("SP-002", "prompt_extraction", 0.6, 0.7, _r(
        r"\brepeat\s+(the\s+|all\s+)?(text|words|everything|content)\s+(above|before)\b"
        r"|\beverything (above|before) this (line|message)\b"
        r"|\b(start|begin) your (answer|response|reply) with\s+[\"']?you are\b"
        r"|\bprint (your|the) (instructions|prompt) verbatim\b"),
        "Verbatim prompt-leak trick", "LLM07"),
    Rule("SP-003", "prompt_extraction", 0.65, 0.75, _r(
        r"\b(r[ée]v[èe]le|affiche|montre|r[ée]p[èe]te|donne|dis|[ée]cris)[\w-]*\b.{0,30}?"
        r"\b(ton|tes|votre|vos)\s+(prompt( syst[èe]me)?|instructions( initiales)?|consignes|message syst[èe]me)\b"),
        "FR : demande de révéler le prompt système", "LLM07"),
    Rule("SP-004", "prompt_extraction", 0.5, 0.75, _r(
        r"\b(reveal|print|output|tell me|give me|send|leak|include|(reply|respond|answer)( only)? with|r[ée]v[èe]le|donne|envoie)\b.{0,40}?"
        r"\b(the|your|le|ton|la|ta)\s+(\w+\s+)?(secret|password|api key|canary|token|mot de passe|cl[ée] api)\b"),
        "Asks the model to disclose a secret it holds", "LLM02"),

    # --- Delimiter / fake role injection -------------------------------------------------
    Rule("DL-002", "delimiter", 0.3, 0.55, _r(
        r"(^|\n)\s*(#{1,6}\s*|\[|\*\*|-{2,}\s*)?(system|developer|admin(istrator)?)\s*(message|prompt|override|instructions?)?"
        r"\s*(\]|:|\*\*|-{2,})", re.IGNORECASE),
        "Fake 'System:' header inside content"),
    Rule("DL-003", "delimiter", 0.35, 0.5, _r(
        r"\bend of (the )?(system )?(prompt|instructions|context)\b|</?\s*(system|instructions|sys)\s*>"
        r"|\bfin (du|des) (prompt|instructions|consignes)\b"),
        "Tries to close the developer context"),

    # --- Exfiltration (LLM02) ------------------------------------------------------------
    Rule("EX-001", "exfiltration", 0.5, 0.75, _r(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=[^)]*\)"),
        "Markdown image with query string: zero-click exfiltration channel", "LLM02"),
    Rule("EX-002", "exfiltration", 0.45, 0.5, _r(
        r"\b(send|post|upload|forward|exfiltrate|transmit|leak|envoie|transf[èe]re)\w*\b.{0,60}?"
        r"\b(to|via|[àa]|vers)\b.{0,25}?(https?://|webhook|\b[\w.-]+@[\w-]+\.[a-z]{2,}\b|attacker|my server|mon serveur)"),
        "Asks to send data to an external destination", "LLM02"),
    Rule("EX-003", "exfiltration", 0.35, 0.65, _r(
        r"\b(append|include|encode|add|put)\b.{0,50}?\b(conversation|chat history|previous messages|secret|password|api key|token|"
        r"user'?s? data)\b.{0,40}?\b(url|link|query string|image|parameter)\b"),
        "Asks to encode conversation data into a URL", "LLM02"),

    # --- Tool coercion / excessive agency (LLM06) ----------------------------------------
    Rule("TA-001", "tool_coercion", 0.3, 0.6, _r(
        r"rm\s+-rf\s+[/~]|curl\s+[^|\n]+\|\s*(ba|z)?sh\b|wget\s+[^|\n]+\|\s*(ba|z)?sh\b|\bnc\s+(-\w+\s+)*-e\b|"
        r"/bin/(ba)?sh\s+-i|powershell(\.exe)?\s+-e(nc|ncodedcommand)?\s"),
        "Destructive or reverse-shell command", "LLM06"),
    Rule("TA-002", "tool_coercion", 0.35, 0.65, _r(
        # "call the X tool ... and delete": the sensitive verb must be chained to the call.
        r"\b(call|invoke|execute|run|use|trigger|appel\w*|utilis\w*|ex[ée]cut\w*)\s+(the\s+|l[ae']\s*)?"
        r"((outil|tool|function|fonction)\s+[\w.-]+|[\w.-]+\s+(tool|function|plugin|outil))\b.{0,40}?"
        r"\b(and|then|to|et|pour|puis)\s+(de\s+)?"
        r"(delete|remove|transfer|send|refund|pay|grant|drop|wipe|purchase|approve|supprim\w*|rembours\w*|envoy\w*)"),
        "Instructs the agent to call a sensitive tool", "LLM06"),

    # --- Indirect: text addressed to the model inside data --------------------------------
    Rule("IN-001", "indirect", 0.3, 0.65, _r(
        r"\b(note|message|instructions?|attention|important)\s+(to|for)\s+(the\s+|any\s+)?(ai|assistant|llm|chatbot|language model|"
        r"gpt|claude|copilot|gemini|agent)s?\b(?!\s+(manager|director|team|coach|teacher|editor|professor))"
        r"|\bif you are an?\s+(ai|llm|language model|assistant|chatbot|agent)\b"
        r"|\b(ai|assistant|llm|agent)s?\s+(reading|processing|summari[sz]ing|analy[sz]ing) this\b"
        r"|\bsi (tu es|vous [êe]tes) une? (ia|assistant|intelligence artificielle|llm)\b"
        r"|\b(note|message) (pour|[àa]) l'?(ia|assistant)\b"),
        "Text addressed to the AI inside content"),
    Rule("IN-002", "indirect", 0.3, 0.6, _r(
        r"\b(do not|don't|never|without)\s+(tell|inform|mention|reveal|let|alert|notify)\w*\b.{0,30}?\bthe user\b"
        r"|\bne (le |lui )?(dis|dites|mentionne|r[ée]v[èe]le)\w* pas\b.{0,30}?\bl'?utilisateur\b"
        r"|\bsans (le )?(dire|pr[ée]venir|informer|avertir)\s+(à\s+)?l'?utilisateur\b"),
        "Asks to hide an action from the user"),
    Rule("IN-003", "indirect", 0.15, 0.55, _r(
        r"\b(act as|you are now|you must now|you will now|your (new )?(role|task|job) is)\b"
        r"|\b(tu dois maintenant|ton (nouveau )?r[ôo]le est|ta (nouvelle )?t[âa]che est)\b"),
        "Second-person command (benign from a user, suspicious inside a document)"),
]

RULES_BY_ID = {r.id: r for r in RULES}
