# Évaluation de bout en bout

`promptfw eval` envoie chaque scénario deux fois : directement au modèle, puis à travers le
proxy `promptfw`. Il mesure l'ASR (taux de réussite des attaques) avec et sans pare-feu,
le taux de blocage, les faux positifs et la latence ajoutée.

```bash
# Vérification de la chaîne de mesure (hors ligne, agent simulé)
promptfw eval --target mock

# Modèle réel via Ollama (à lancer sur une machine disposant du modèle)
promptfw eval --target openai --base-url http://localhost:11434 --model llama3.2 --repeat 3
```

- `scenarios/attacks.yaml`, `scenarios/benign.yaml` : scénarios et critères de réussite.
- `policy.yaml` : politique utilisée ; le secret du prompt système est ajouté aux canaries à l'exécution.
- `results/` : rapports JSON, CSV et Markdown. Seuls des résultats réellement mesurés y sont versionnés.

Les résultats de la cible `mock` ne mesurent pas la sécurité : l'agent simulé n'obéit qu'à des
instructions explicites. Ils servent uniquement à vérifier que la chaîne de mesure fonctionne.
