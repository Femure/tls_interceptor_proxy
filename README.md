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
- Corriger le pb de UTF-8
- Améliorer l'enregistrement des données loggées
- Récupérer l'IP de celui qui à envoyer la requête compromettante