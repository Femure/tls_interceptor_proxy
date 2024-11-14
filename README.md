**Fait :**

- Mise en place du proxy TLS interceptor.
- Mise en place de logs en continu.
- Réussi à bloquer une requête.
- Renvoyé une réponse au client pour une condition donnée (ici par rapport au nom de domaine).
- Filtré les requêtes pour ne garder qu'un domaine visé (ex : chatgpt.com).
- Ciblé uniquement les requêtes POST.
- Réussi à extraire les données de la requête pour les envoyer en analyse.
- Loggé uniquement les requêtes détectées comme anormales.
- Renvoyé une réponse dans le même format que ChatGPT pour avertir le client que la requête est interdite.
- Récupéré l'IP de l'expéditeur de la requête compromettante.
- Amélioré l'enregistrement des données loggées.
- Création d'un Dockerfile pour déployer l'application dans un conteneur.
- Ajout des fichiers du crate modifié en local pour garder les modifications lors du déploiement.
- Implémentation des GitHub Actions (Linter, Build, Test, Package).
- Implémentation de certains tests unitaires.
- Modification du shell de setup.
- Réorganisation de la modularité du code.
---
**À faire :**

- Rendre le code et le proxy sécurisés.
- Implémentation des tests unitaires.
- Ajouter la GitHub Action pour scanner les vulnérabilités.
---
**Problèmes rencontrés :**

- Lorsqu'un utilisateur envoie des infos confidentielles dans une nouvelle conversation ChatGPT, la conversation n'a pas encore d'ID. Il a fallu en créer un, puis faire en sorte qu'elle possède un titre ("New conversation") et qu'elle soit enregistrée dans la base de données avec les autres prompts. Pour le moment, je n'arrive pas à l'enregistrer dans la base pour le charger après un refresh.
- La récupération de l'IP n'est pas implémentée dans le service proxy du crate, et je ne peux pas envelopper la couche MITM avec le service qui récupère l'IP du client. Il a donc fallu modifier le code du crate pour ajouter cette fonctionnalité. Je cherche encore un moyen de faire ça plus proprement.
- Forger la réponse lorsque l'utilisateur envoie un prompt avec des informations compromettantes. Il fallait intercepter la réponse de base de ChatGPT pour comprendre comment est construite la réponse, copier les éléments et simplement modifier les informations utiles.
- Bloquer la requête : pour cela, il fallait mettre des conditions sur la requête envoyée (hôte : chatgpt.com, chemin de l'URL : /backend-api/conversation, méthode : POST). Une fois les conditions établies, au lieu de laisser passer la requête, j'ai créé une réponse simple avec le code de statut approprié.
