Fait:
- Mise en place du proxy TLS interceptor
- Mise en place de logs en continue
- Réussir à bloquer une rêquete
- Renvoyer une réponse à au client pour un condition donnée (ici par rapport au nom de domain)
- Filtrer les requêtes pour ne garder qu'un domain visé ex:chatgpt.com
- Viser seulement les requêtes POST
- Réussir à extraire les données de la requête pour ensuite les envoyer en analyse
- Ne logger que les réquêtes détecter comme anormale
- Renvoyer une réponse dans le même format que chatgpt pour avertir le client que la requête est interdite
- Récupérer l'IP de celui qui a envoyé la requête compromettante
- Améliorer l'enregistrement des données loggées
- Création d'un Dockfile pour déployer l'application dans un conteneur
- Ajout des fichiers du crate modifié en local pour garder les modifications lors du déploiement

A faire: 
- Rendre le code et le proxy sécurisés
- Nettoyer le code (supprimer les dépendences inutiles, améliorer la lisibilité du code...)

Problèmes recontrés: 
- Lorsqu'un utilisateur envoye des infos confidentielles dans une nouvelle conversation Chatgpt
la conversation n'a pas encore d'ID. Il a donc fallu en créer un et ensuite faire en sorte qu'elle possède un
titre ici "New conversation" et qu'elle soit enregistrée dans la base de données avec les autres prompts. Pour le
moment, je n'arrive pas à l'enregistrer dans la base pour le charger après un refresh.
- La récupération de l'IP car ce n'est pas implémenté dans le service proxy
du crate et je ne peux pas envelopper la couche mitm avec le service qui récupère l'IP du client.
Je suis donc obligé de modifier le code du crate pour ajouter cette fonctionnalité. Il était impossible 
de d'envoyer l'adresse IP du client au travers des services implémentés dans le crate du proxy. Il a donc
fallu passer l'adresse IP au travers d'une méthode du crate. Je cherche encore un moyen de faire ça plus
proprement.
- Forger la requête réponse lorsque l'utilisateur envoie un prompt sur Chatgpt avec des infos
comprettante. Je devais intercepter la réponse de base de Chatgpt pour comprendre comment est construit
la réponse afin de copier les éléments et de simplement modifier les informations utiles.
- Réussir à bloquer la requête. Pour ça il fallait déjà mettre des conditions sur la requête envoyée,
ici c'est sur l'hôte (chatgpt.com), sur le chemin de l'URL (/backend-api/conversation) et sur la méthode (POST).
Une fois les conditions établies au départ au lieu de laisser passer la requête je crée une réponse simple avec
le code
