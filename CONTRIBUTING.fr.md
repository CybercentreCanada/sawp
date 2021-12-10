# [ENGLISH](CONTRIBUTING.md)

# Contribution

Ce projet est maintenu activement et accepte les contributions de source ouverte.

Tout changement prévu doit faire l’objet d’une discussion. Pour ce faire, créez un problème ou
communiquez directement avec nous pour confirmer que personne ne travaille sur cette même fonctionnalité
et que le changement proposé correspond à la vision que nous avons adoptée pour la bibliothèque.

Tous les contributeurs doivent se conformer à un certain code de conduite. Prière de lire le [Code
de conduite de Rust](https://www.rust-lang.org/fr/policies/code-of-conduct) à titre d’exemple.

En contribuant à ce projet, vous reconnaissez que toutes les contributions seront effectuées en
vertu du contrat de licence inclus dans le fichier LICENSE.

## Consignes

La liste de vérification [Rust API Guidelines
Checklist](https://rust-lang.github.io/api-guidelines/checklist.html) (en anglais seulement) propose
un survol des pratiques exemplaires et des conventions d’affectation des noms à adopter.

### Messages liés aux commits

- Les commits devraient se limiter à une fonction logique ou à une résolution de bogue.
- Le code ne devrait pas être déplacé et modifié dans le même commit.
- Veuillez conserver un historique git clair, descriptif et bref. Effectuez un squash au besoin.
- Incluez les erreurs de compilation ou les étapes nécessaires pour reproduire l’erreur le cas
  échéant.
- Le titre des commits ne devrait pas dépasser 50 caractères et inclure le module/la zone et une
  brève description. Le commit peut alors être décrit en détail dans le corps.

``` 
module: brève description

Ajouter une description du commit.  
```

### Pull Requests

- Dans la plupart des cas, une demande de tirage (pull request) devrait se limiter à une fonction
  logique ou à une résolution de bogue.
- Veuillez utiliser le modèle [dupliquer et
  tirer](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/about-collaborative-development-models)
(en anglais seulement) pour ouvrir les demandes de tirage dans github.
- Assurez-vous que votre branche est à jour avec la branche `main` en utilisant la fonction `git
  rebase -i main` afin d'évitez une fusion (git merge). Vous pouvez forcer l’envoi (push) de ces
changements vers la branche de votre fourche (fork).
- Il est possible d’effectuer des changements après l'ouverture d'une demande de tirage.
- Nous effectuerons soit une « fusion squash » ou une « fusion de rebase » avec votre demande de
  tirage une fois qu’elle aura été acceptée.

Il sera plus facile de passer en revue une demande de tirage si elle est bien documentée :

- Décrivez entièrement la fonction ou la résolution de bogue;
- Ajoutez un exemple d’utilisation, d’entrée ou de sortie, le cas échéant;
- Ajoutez des liens vers les problèmes, les demandes de tirage et les documents externes pertinents
  comme les spécifications du protocole citées en référence.

### Style de code

Utiliser `cargo fmt --all` pour le formatage du code.

À moins qu’il n’y ait une bonne raison de faire autrement, il convient de respecter les directives
générales en matière de style :

- La longueur des lignes ne devrait pas dépasser 100 caractères (en tenant compte des commentaires).
- Les noms de variables devraient être descriptifs.

Il est préférable d’ajouter des commentaires sur la ligne précédente que des commentaires de fin :

_Préférable_
```rust
// Commentaire sur la valeur utilisée.
let value = 10;
```

_Éviter_
```rust
let value = 10; // Commentaire sur la valeur utilisée.
```

### Tests et assurance de qualité

Nous nous engageons à maintenir un certain niveau de qualité en ce qui a trait au code. Veuillez
inclure les tests unitaires de manière à fournir le plus de détails possible concernant la fonction
ou la résolution de bogue.
