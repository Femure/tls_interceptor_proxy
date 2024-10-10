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

A faire: 
- Améliorer l'enregistrement des données loggées
- Récupérer l'IP de celui qui à envoyer la requête compromettante

Problèmes recontrés: 
- La récupération de l'IP car ce n'est pas implementé dans le service proxy
du crate et je ne peux pas envelopper la couche mitm avec le service qui récupère l'IP du client.
Je suis donc obligé de modifier le code du crate pour ajouter cette fonctionnalité mais pour le 
moment je n'arrive pas récupérer l'adresse IP du client une fois que je l'ajoute aux extensions de 
la requête http.
- Forger la requête réponse lorsque l'utilisateur envoie un prompt sur Chatgpt avec des infos
comprettante. Je devais intercepter la réponse de base de Chatgpt pour comprendre comment est construit
la réponse afin de copier les éléments et de simplement modifier les informations utiles.
- Réussir à bloquer la requête. Pour ça il fallait déjà mettre des conditions sur la requête envoyée,
ici c'est sur l'hôte (chatgpt.com), sur le chemin de l'URL (/backend-api/conversation) et sur la méthode (POST).
Une fois les conditions établies au départ au lieu de laisser passer la requête je crée une réponse simple avec
le code 