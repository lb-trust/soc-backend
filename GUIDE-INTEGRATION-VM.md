# Relier le backend SOC, Wazuh et IRIS DFIR

Ce guide décrit le raccordement de trois machines virtuelles :

1. **VM Backend SOC** : exécute `script1.py` et stocke ses données dans SQLite.
2. **VM Wazuh** : héberge Wazuh et son **Wazuh Indexer**.
3. **VM IRIS DFIR** : reçoit les analyses automatiques dans la timeline d'un cas.

Le backend interroge périodiquement l'API du Wazuh Indexer en lecture. Il ne se
connecte pas aux agents Wazuh et ne nécessite pas de transfert direct depuis le
manager. Les alertes sont enregistrées et corrélées par le backend. IRIS ne reçoit
pas chaque alerte : le backend publie uniquement les analyses automatiques Ollama
déclenchées par les seuils décrits plus bas.

## 1. Schéma et flux

```text
Agents Wazuh ──> Wazuh Manager / Indexer (VM Wazuh)
                               ▲
                               │ HTTPS, TCP 9200 (lecture des alertes)
                               │
                    Backend SOC (VM Backend)
                       │              │
                       │              └──> Ollama (local par défaut, TCP 11434)
                       │                    analyse automatique des incidents
                       │
                       └── HTTPS, TCP 443 ou 8443 ──> IRIS DFIR (VM IRIS)
                            publication d'un événement dans la timeline
```

Les ports indiqués sont des valeurs courantes, à confirmer selon la configuration
de vos VM :

| Source | Destination | Port/protocole | Usage |
| --- | --- | --- | --- |
| Backend SOC | Wazuh Indexer | TCP 9200, HTTPS | Lire les index d'alertes Wazuh. |
| Backend SOC | IRIS DFIR | TCP 443 ou 8443, HTTPS | Publier une analyse dans la timeline. |
| Backend SOC | Ollama | TCP 11434, HTTP par défaut | Analyser un incident avant publication IRIS. |
| Poste d'administration | Backend SOC | TCP 8080 ou port HTTPS du reverse proxy | Appeler l'API du backend. |

N'ouvrez pas ces ports à tout le réseau : limitez les règles du pare-feu aux IP
des VM qui en ont besoin. Les ports Wazuh des agents (par exemple 1514/1515)
servent à la communication des agents avec Wazuh ; ils ne sont pas requis pour le
raccordement du backend à l'Indexer.

## 2. Préparer les VM

Attribuez des adresses IP stables ou des noms DNS internes et vérifiez que les VM
peuvent se joindre sur les ports nécessaires. Dans les exemples ci-dessous,
remplacez les valeurs par celles de votre réseau :

| VM | Exemple d'adresse | À remplacer par |
| --- | --- | --- |
| Backend SOC | `192.168.10.20` | IP réelle de la VM Python |
| Wazuh Indexer | `192.168.10.30` | IP/DNS et port réels de l'Indexer |
| IRIS DFIR | `192.168.10.40` | IP/DNS et port HTTPS réels d'IRIS |

Depuis la VM Backend SOC, testez la résolution et l'accès réseau :

```bash
getent hosts wazuh-indexer.example.lan iris.example.lan
curl -sS -o /dev/null -w 'Indexer: HTTP %{http_code}\n' \
  https://wazuh-indexer.example.lan:9200/
curl -sS -o /dev/null -w 'IRIS: HTTP %{http_code}\n' \
  https://iris.example.lan:8443/
```

Un code HTTP `401` ou `403` peut confirmer que le service répond mais que
l'authentification manque ou n'a pas les droits requis. Une erreur TLS peut
indiquer que le certificat de l'instance n'est pas approuvé : installez la CA
interne sur la VM Backend plutôt que de désactiver la vérification TLS.

## 3. Préparer Wazuh

1. Vérifiez que le Wazuh Indexer est actif et joignable depuis la VM Backend.
2. Identifiez l'URL HTTPS de l'Indexer. En installation standard, son port est
   souvent `9200`; l'adresse de l'Indexer peut être différente de celle du
   manager.
3. Créez ou choisissez un compte de service ayant **uniquement les droits de
   lecture** sur les index d'alertes requis.
4. Vérifiez que le certificat HTTPS de l'Indexer est approuvé par le système de
   la VM Backend.

La collecte utilise par défaut le motif d'index `wazuh-alerts-*` et lit les
événements du champ `timestamp` sur une période récente. Elle se répète toutes
les 60 secondes par défaut (minimum 15 secondes). Le backend déduplique les
événements Wazuh identifiés par leur ID afin que les collectes qui se chevauchent
ne gonflent pas artificiellement les compteurs.

## 4. Préparer IRIS DFIR

1. Vérifiez que l'instance IRIS répond en HTTPS depuis la VM Backend.
2. Créez une clé API pour un compte de service autorisé à ajouter des événements
   de timeline au cas concerné.
3. Relevez l'identifiant **numérique** du cas IRIS cible.
4. Faites approuver le certificat TLS d'IRIS par le système de la VM Backend.

`IRIS_BASE_URL` doit être l'origine HTTPS seulement, sans chemin et sans slash
final, par exemple `https://iris.example.lan:8443`. Le backend appelle ensuite
l'API d'ajout d'événement à la timeline du cas configuré. Ne mettez jamais la
clé API dans le dépôt ou dans un fichier de configuration versionné.

## 5. Installer le backend sur sa VM

Depuis la racine du dépôt, sur la VM Backend :

```bash
python3 --version
```

Python 3.10 ou plus récent est recommandé. Le script utilise la bibliothèque
standard de Python ; aucun paquet Python externe n'est nécessaire.

Transférez le dépôt de manière sûre sur cette VM, puis placez-vous dans son
répertoire. Préparez un jeton API aléatoire et distinct des identifiants Wazuh
et IRIS. Définissez les variables d'environnement dans le shell qui lancera le
backend (exemple Bash) :

```bash
export SOC_TENANTS_JSON='{"REMPLACER_PAR_UN_JETON_LONG_ET_ALEATOIRE":"client-a"}'
export SOC_HOST='0.0.0.0'
export SOC_PORT='8080'
export SOC_DB_PATH='/var/lib/soc-backend/soc.db'
export WAZUH_POLL_SECONDS='60'
export WAZUH_SOURCES_JSON='[{"tenant_id":"client-a","url":"https://wazuh-indexer.example.lan:9200","username":"soc-reader","password":"REMPLACER_PAR_LE_SECRET","verify_tls":true,"alerts_index":"wazuh-alerts-*","batch_size":100}]'

export IRIS_BASE_URL='https://iris.example.lan:8443'
export IRIS_API_KEY='REMPLACER_PAR_LA_CLE_API_IRIS'
export IRIS_CASE_ID='123'

python3 ./script1.py
```

Adaptez `tenant_id` (`client-a`) à l'identifiant client déclaré dans
`SOC_TENANTS_JSON`. Pour plusieurs clients, ajoutez une paire jeton/client dans
`SOC_TENANTS_JSON` et une source Wazuh par client dans `WAZUH_SOURCES_JSON`.
Chaque source doit contenir `tenant_id`, `url`, `username` et `password`.

La variable `verify_tls` doit rester à `true` en environnement normal. N'utilisez
pas de compte administrateur Wazuh pour la collecte. Les valeurs d'exemple
ci-dessus sont des espaces réservés, pas des identifiants à réutiliser.

`SOC_HOST=0.0.0.0` permet aux autres machines d'atteindre le serveur, mais le
backend fourni écoute en HTTP sans chiffrement. N'exposez pas directement le
port 8080 à un réseau non fiable : placez un reverse proxy HTTPS devant lui,
restreignez les accès par pare-feu et ne rendez pas l'API accessible depuis
Internet. Le jeton du backend est transmis dans l'en-tête
`Authorization: Bearer <jeton>`.

Pour un lancement persistant, utilisez un gestionnaire de services (par exemple
systemd) et stockez les secrets dans un fichier de variables protégé par des
permissions strictes et exclu du dépôt. N'affichez pas les secrets dans les
journaux ou dans les commandes partagées.

## 6. Prérequis Ollama pour la publication IRIS

Le script utilise Ollama pour générer l'analyse qui sera publiée dans IRIS.
Par défaut, il cherche Ollama sur la **même VM** que le backend à
`http://127.0.0.1:11434`, avec le modèle `llama3.1`. Il faut donc soit installer
et démarrer Ollama et le modèle sur la VM Backend, soit configurer `OLLAMA_URL`
vers une instance Ollama joignable et autorisée depuis cette VM :

```bash
export OLLAMA_URL='http://127.0.0.1:11434'
export OLLAMA_MODEL='llama3.1'
```

Si Ollama est sur une autre VM, configurez l'URL réseau correspondante et
limitez son accès au seul backend. Le transport HTTP par défaut ne chiffre pas
les échanges : ne l'utilisez pas sur un réseau non fiable sans protection
adaptée.

La publication IRIS est désactivée si l'une des variables
`IRIS_BASE_URL`, `IRIS_API_KEY` ou `IRIS_CASE_ID` manque. Une fois les trois
configurées, le backend publie une analyse automatique après traitement Ollama
pour les alertes de niveau Wazuh supérieur ou égal à 10, ou lorsque 40 alertes
de niveau inférieur à 10 sont regroupées dans la fenêtre prévue. L'analyse
manuelle par l'API ne déclenche pas de publication IRIS.

## 7. Vérifier le raccordement

### Santé du backend

Depuis la VM Backend :

```bash
curl -fsS http://127.0.0.1:8080/health
```

Résultat attendu : `{"status":"ok"}`. Depuis une autre VM ou un poste autorisé,
utilisez l'adresse IP du backend et le port exposé (ou l'URL HTTPS du reverse
proxy).

### Accès authentifié à l'API

Dans le shell où le jeton est défini, vérifiez l'API :

```bash
curl -fsS \
  -H "Authorization: Bearer ${SOC_API_TOKEN}" \
  http://127.0.0.1:8080/api/dashboard
```

Pour cet exemple, définissez `SOC_API_TOKEN` avec le même jeton que celui
configuré dans `SOC_TENANTS_JSON`. En production, appelez l'URL HTTPS du reverse
proxy depuis un réseau autorisé.

### Collecte Wazuh et publication IRIS

1. Consultez les journaux du processus backend et vérifiez qu'ils indiquent une
   collecte Wazuh réussie pour le bon client.
2. Après ingestion, vérifiez les alertes avec `GET /api/alerts` et les incidents
   avec `GET /api/incidents`, en envoyant le jeton Bearer.
3. Vérifiez que le compte Ollama et le modèle configuré répondent depuis la VM
   Backend.
4. Pour tester le flux IRIS de bout en bout, faites générer une analyse
   automatique en respectant les seuils configurés. Vérifiez ensuite
   l'événement dans la timeline du cas cible et les journaux en cas d'échec.

Une simple alerte de faible niveau ne provoque donc pas immédiatement un
événement IRIS. En cas d'échec de publication, le backend réessaie jusqu'à trois
fois ; les erreurs sont consignées dans ses journaux.

## Dépannage

| Symptôme | Vérifications |
| --- | --- |
| Aucun accès au port 9200 | Adresse/port de l'Indexer, pare-feu, routage et écoute HTTPS. |
| Erreur 401/403 Wazuh | Identifiants du compte de lecture et droits sur `wazuh-alerts-*`. |
| Erreur de certificat Wazuh ou IRIS | Installer la CA/certificat approprié sur la VM Backend ; garder la validation TLS activée. |
| Aucune alerte importée | `WAZUH_SOURCES_JSON`, `tenant_id`, droits d'index, champ `timestamp` et journaux de collecte. |
| API backend inaccessible depuis le réseau | `SOC_HOST`, pare-feu, port `SOC_PORT` et reverse proxy éventuel. |
| Pas d'événement dans IRIS | Configuration complète des trois variables IRIS, droits du compte sur le cas, seuil atteint, Ollama joignable et journaux backend. |

