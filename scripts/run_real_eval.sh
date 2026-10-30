#!/usr/bin/env bash
# Mesure de bout en bout avec un modèle réel servi par Ollama.
# Usage : scripts/run_real_eval.sh [modele] [repetitions]
set -euo pipefail

MODEL="${1:-llama3.2}"
REPEAT="${2:-3}"
BASE_URL="${OLLAMA_URL:-http://localhost:11434}"

command -v promptfw >/dev/null || { echo "promptfw introuvable : activez l'environnement (source .venv/bin/activate)"; exit 1; }
curl -sf "$BASE_URL/api/tags" >/dev/null || { echo "Ollama ne répond pas sur $BASE_URL (lancez : ollama serve)"; exit 1; }
curl -sf "$BASE_URL/api/tags" | grep -q "\"$MODEL" || { echo "Modèle $MODEL absent : ollama pull $MODEL"; exit 1; }

echo "Modèle : $MODEL | répétitions : $REPEAT | endpoint : $BASE_URL"
promptfw eval --target openai --base-url "$BASE_URL" --model "$MODEL" --repeat "$REPEAT" --out eval/results
echo
echo "Rapports écrits dans eval/results/ (JSON, CSV, Markdown)."
