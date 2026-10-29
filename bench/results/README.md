# Résultats de benchmark archivés

Chaque fichier est la sortie brute de `promptfw bench --explain`, conservée pour la traçabilité.

| Fichier | Contexte |
|---|---|
| `2026-10-29_p0_baseline.txt` | Première exécution du jeu `holdout`, avant toute correction P0 |
| `2026-10-29_p0_after.txt` | Après les corrections P0 (limites de taille, URL sans schéma et `user@`, images par référence et HTML, typage strict, proxy) |

Lecture : le jeu `dev` a servi à régler les règles et donne une estimation optimiste. Le jeu
`holdout` n'a jamais servi au réglage des règles d'`ingress` ; voir `bench/corpus/holdout/README.md`
pour les cas contaminés par une correction ultérieure. La latence mesure le pare-feu seul,
sans appel réseau ni modèle, sur la machine d'exécution du benchmark.
