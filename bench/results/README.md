# Résultats de benchmark archivés

Chaque fichier est la sortie brute de `promptfw bench --explain`, conservée pour la traçabilité.

| Fichier | Contexte |
|---|---|
| `2026-10-29_p0_baseline.txt` | Première exécution du jeu `holdout`, avant toute correction P0 |
| `2026-10-29_p0_after.txt` | Après les corrections P0 (limites de taille, URL sans schéma et `user@`, images par référence et HTML, typage strict, proxy) |
| `2026-10-30_p1_after.txt` | Après P1 (autorisation, identité signée, provenance, normalisation renforcée par les tests de propriétés) |
| `2026-10-30_p1_complements.txt` | Après les compléments du P1 (attributs, origines par outil, export, p95) |
| `2026-10-30_mutmut.md` | Tests de mutation sur le code de décision : score et analyse des survivants |
| `2026-10-30_p3_cache_latency.md` | Effet du cache des lectures sur la latence du pare-feu |
| `2026-10-30_p1_fuzz_seed1.txt` | `promptfw fuzz --n 500 --seed 1` : 500 attaques composées générées, décision d'entrée uniquement |

Lecture : le jeu `dev` a servi à régler les règles et donne une estimation optimiste. Le jeu
`holdout` n'a jamais servi au réglage des règles d'`ingress` ; voir `bench/corpus/holdout/README.md`
pour les cas contaminés par une correction ultérieure. La latence mesure le pare-feu seul,
sans appel réseau ni modèle, sur la machine d'exécution du benchmark.
