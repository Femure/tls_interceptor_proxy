Fait:
- Mise en place du proxy TLS interceptor
- Mise en place de logs en continue
- Réussir à bloquer une rêquete
- Renvoyer une réponse à au client pour un condition donnée (ici par rapport au nom de domain)
- Filtrer les requêtes pour ne garder qu'un domain visé ex:chatgpt.com
- Viser seulement les requêtes POST
- Réussir à extraire les données de la requête pour ensuite les envoyer en analyse

A faire: 
- Corriger le pb de UTF-8
- Ne logger que les réquêtes détecter comme anormale
- Améliorer l'enregistrement des données loggées
- Renvoyer une réponse dans le même format que chatgpt pour avertir le client que la requête est interdite