# Backend SOC augmenté 

`script1.py` fournit une API HTTP Python autonome (bibliothèque standard uniquement).
Pour relier le backend installé sur une VM à Wazuh et IRIS DFIR sur des VM séparées,
consultez le [guide d'intégration des VM](./GUIDE-INTEGRATION-VM.md).
Elle conserve Wazuh comme source et tableau de bord, sépare les données par client,
dédoublonne et corrèle les alertes, calcule un score, conserve incidents et retours,
et peut demander une analyse à une instance Ollama locale. Les alertes identiques
(même client, même règle et même agent) sont regroupées, toutes IP sources confondues.
Les alertes de niveau inférieur à 10 sont regroupées pendant six heures et ne
déclenchent Ollama qu'à partir de 40 occurrences distinctes dans cette fenêtre.
Les alertes de niveau 10 ou plus sont analysées immédiatement. Les identifiants
Wazuh déjà collectés sont dédupliqués pour éviter qu'un chevauchement de collecte
gonfle artificiellement le compteur.

Après une analyse automatique Ollama réussie, le backend peut publier un événement
détaillé dans la timeline d'un cas IRIS DFIR existant. Les alertes ne sont donc jamais
envoyées directement à IRIS : seules les alertes répondant aux règles ci-dessus sont
analysées puis publiées. L'événement IRIS contient l'analyse Ollama dans le résumé et
les données enrichies (compteurs, IP sources, alertes associées) dans les détails.
L'intégration IRIS reste désactivée tant que `IRIS_BASE_URL`, `IRIS_API_KEY` et
`IRIS_CASE_ID` ne sont pas tous configurés.

L'analyse manuelle via `/api/incidents/{id}/analyze` reste disponible, mais ne publie
pas automatiquement dans IRIS. Les analyses automatiques et publications échouées
sont réessayées jusqu'à trois fois sans bloquer la réception des alertes.

## Démarrage

Python 3.10 ou plus récent est recommandé. Dans PowerShell, définissez au minimum
un jeton API par client avant de lancer le serveur :

```powershell
$env:SOC_TENANTS_JSON='{"remplacer-par-un-jeton-long-et-aleatoire":"client-a"}'
python .\script1.py
```

Le serveur écoute par défaut sur `127.0.0.1:8080`; la base SQLite est créée dans
`soc.db`. Configurez `SOC_HOST` pour une autre interface réseau et protégez alors
l'accès avec HTTPS via un reverse proxy. N'exposez jamais le serveur directement
sur Internet. Les jetons sont fournis dans l'en-tête `Authorization: Bearer ...`.

## Configuration facultative

| Variable | Défaut | Description |
| --- | --- | --- |
| `SOC_TENANTS_JSON` | `{}` | Objet JSON `jeton: identifiant_client`; obligatoire au démarrage. |
| `SOC_DB_PATH` | `soc.db` | Emplacement de la base SQLite. |
| `SOC_HOST` / `SOC_PORT` | `127.0.0.1` / `8080` | Adresse et port d'écoute. |
| `WAZUH_SOURCES_JSON` | `[]` | Sources Wazuh Indexer à interroger périodiquement. |
| `WAZUH_POLL_SECONDS` | `60` | Intervalle minimum de collecte (15 secondes). |
| `SOC_WEBHOOKS_JSON` | `{}` | Objet JSON `identifiant_client: URL_webhook`. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | URL de l'instance Ollama recevant le contexte d'incident. |
| `OLLAMA_MODEL` | `llama3.1` | Modèle Ollama utilisé pour les analyses automatiques et manuelles. |
| `IRIS_BASE_URL` | désactivé | URL HTTPS de l'instance IRIS DFIR, sans slash final. |
| `IRIS_API_KEY` | désactivé | Clé API IRIS, fournie dans l'en-tête Bearer et jamais journalisée. |
| `IRIS_CASE_ID` | désactivé | Identifiant numérique du cas IRIS recevant les événements de timeline. |

Exemple de collecte via l'API Wazuh Indexer (port 9200 dans une installation standard) :

```powershell
$env:WAZUH_SOURCES_JSON='[{"tenant_id":"client-a","url":"https://192.168.5.59/","username":"admin","password":"admin","verify_tls":true,"alerts_index":"wazuh-alerts-*","batch_size":100}]'
```

Le compte Indexer doit avoir les droits de lecture sur les index d'alertes. Le filtre
par défaut récupère les événements récents (`timestamp`) et peut être adapté à votre
politique de rétention. Évitez `verify_tls: false` hors environnement de développement.
Les mots de passe Wazuh et les jetons doivent venir d'un gestionnaire de secrets en
production, pas d'un fichier versionné.

## API

Toutes les routes `/api/...` exigent le jeton Bearer et ne retournent que les données
du client auquel ce jeton est associé.

| Méthode et route | Usage |
| --- | --- |
| `GET /health` | Vérification de disponibilité (sans authentification). |
| `GET /api/dashboard` | Compteurs globaux et niveaux de priorité du client. |
| `GET /api/alerts?limit=100&since=...` | Alertes récentes, filtrées par client. |
| `POST /api/alerts` | Ingestion manuelle d'une alerte JSON Wazuh. |
| `GET /api/incidents?status=open&limit=100` | Incidents récents et filtre de statut facultatif. |
| `GET /api/incidents/{id}` | Détail isolé par client : alertes associées et historique/feedback. |
| `PATCH /api/incidents/{id}` | Mise à jour de `status` et/ou ajout de `feedback`. |
| `POST /api/incidents/{id}/analyze` | Analyse contextuelle par Ollama. |

Les statuts acceptés sont `open`, `investigating`, `resolved` et `false_positive`.
Les niveaux de sévérité des incidents sont calculés automatiquement à partir du niveau
Wazuh et des occurrences corrélées. La corrélation d'incidents utilise l'agent ou
l'adresse IP source dans une fenêtre de 30 minutes. Le regroupement des alertes est
basé sur le client, la règle et l'agent : fenêtre glissante de six heures pour les
niveaux Wazuh inférieurs à 10, et de 30 minutes à partir du niveau 10. Le détail expose
`occurrences` (total du groupe), `occurrences_6h` (compteur glissant utilisé pour le
seuil), `source_ips` et `source_ip_counts` (IP distinctes et compteurs sur six heures).

Pour IRIS DFIR, le compte de service doit pouvoir écrire des événements de timeline
dans le cas cible. Configurez la nouvelle clé API localement, par exemple dans
PowerShell, sans la placer dans un fichier versionné :

```powershell
$env:IRIS_BASE_URL='https://adresse-de-votre-iris:8443'
$env:IRIS_API_KEY='clé-api-stockée-localement'
$env:IRIS_CASE_ID='123'
```

Faites confiance au certificat TLS de l'instance IRIS dans le système hôte ; la
vérification TLS est activée et n'est pas désactivée par le backend.
