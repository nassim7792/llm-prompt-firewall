# Cache des lectures normalisées : effet sur la latence

Mesure : 5 passages sur les 172 cas `ingress` du corpus (dev + holdout),
puis 5 inspections d'un span `DATA` de 45 000 caractères. Machine de développement, Python 3.13, deux exécutions par configuration.

| Configuration | Cas du corpus, p50 | Cas du corpus, p95 | Span de 45 000 caractères, médiane |
|---|---|---|---|
| Sans cache | 0,57 / 0,60 ms | 1,02 / 1,33 ms | 399,7 / 396,9 ms |
| Avec cache par inspection | 0,47 / 0,48 ms | 0,87 / 0,95 ms | 282,4 / 279,6 ms |

Gain observé : environ −17 % en médiane sur les cas courts, environ −29 % sur un long span, ce qui correspond
à la suppression du second calcul de la clôture (`provenance` réutilise celle d'`ingress`). Le test
`tests/test_cache.py` vérifie qu'aucun verdict du corpus ne change avec le cache.
