# Jeu d'évaluation séparé (holdout)

Ces cas ont été rédigés **après** le réglage des règles et n'ont jamais servi à les ajuster.
Ils servent uniquement à mesurer la généralisation. Règle à respecter : si un cas de ce
dossier est mal classé, on ne modifie pas les règles pour le faire passer. On documente
l'échec, et on ajoute éventuellement un cas similaire au corpus `dev/` avant tout réglage.

## Cas contaminés

Un cas est dit contaminé lorsqu'une correction du code a été faite **après** avoir vu
son échec sur ce jeu. Son résultat ultérieur n'est plus une mesure indépendante.

| Cas | Correction | Prévue avant le holdout ? |
|---|---|---|
| `h-ue-03` | Détection des URL sans schéma | Oui (audit, point V5) |
| `h-ue-04` | Hôte réel après `user@` dans une URL | **Non**, découvert grâce au holdout |
| `h-ep-04` | Décodage de l'encodage URL même lorsque les `%XX` ne sont pas contigus | Non. Correction motivée par les tests de propriétés (P1.4), mais l'échec de ce cas était déjà connu |
