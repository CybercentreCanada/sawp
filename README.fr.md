# [English](README.md)

# Bibliothèque d’analyse des protocoles filaires adaptés à la sécurité.

Cette bibliothèque contient des analyseurs de protocoles filaires utilisée principalement par les
capteurs de sécurité d’un réseau.

Chaque analyseur présente une interface commune qui permet au moteur des capteurs d’alimenter
l’analyseur en octets et de renvoyer les métadonnées analysées. Comme on s’attend à ce que les
octets se trouvent sur la couche session, le moteur doit assembler les données sur la couche
transport en une charge utile de session qui sera alors transmise à la bibliothèque.

Cette bibliothèque vise à assurer la résilience et à analyser le plus grand nombre possible des
messages observés in vivo. Si un message est non valide ou non conforme, il ne devrait pas être
rejeté par l’analyseur. Les analyseurs ajouteront des indicateurs au message advenant l’échec de la
validation plutôt que de générer une erreur.

L’interface de chaque analyseur est uniforme et simple. Elle se compose de quelques fonctions
permettant de faire ce qui suit :

- vérifier si ne charge utile correspond ou non au protocole en question (p. ex. s’agit-il du
  protocole MODBUS?);
- fournir un plus grand nombre d’octets à l’analyseur;
- définir les rappels à évoquer lors d’événements de métadonnées selon le protocole (tâche);
- indiquer que certains octets ne sont pas accessibles (c.-à-d., notification lors d’une perte de
  paquets) (tâche);
- indiquer qu’une session a pris fin (tâche).

La bibliothèque présente les liaisons Rust et C pour une intégration plus facile aux plateformes de
capteurs de sécurité réseau existantes et à venir. (tâche)

# Utilisation
Pour commencer à utiliser SAWP, ajoutez un analyseur aux dépendances `Cargo.toml` de
vos projets. La bibliothèque de base sera également nécessaire à l’utilisation de types courants.

**La version minimale prise en charge de `rustc` est `1.63.0`.**

## Exemple 
``` 
[dependencies]
sawp-modbus = "0.8.0"
sawp = "0.8.0"
```

## Prise en charge d’une interface de fonction extérieure (FFI)
Certains analyseurs font appel à une interface de fonction extérieure
(FFI pour Foreign Function Interface) pour les projets C/C++.  Il
est possible d’activer la prise en charge d’une FFI au moyen de la fonction `ffi`.

Un fichier [Makefile](Makefile) est également fourni pour faciliter le processus de compilation.
Veuillez consulter ce fichier pour une documentation plus détaillée.

``` 
# Installer cbindgen, qui est nécessaire pour générer les en-têtes
cargo install --force
cbindgen

# Générer les en-têtes et les objets partagés
make
```

# Contribution

Ce projet est maintenu activement et accepte les contributions de source ouverte.  Voir le fichier
[CONTRIBUTION](CONTRIBUTING.fr.md) pour plus de détails.
