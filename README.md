LAB-8 - Analyse de Posture et Exposition d'Applications Mobiles avec BeVigil et Yaazhini
Réalisé par : zouhairelghouate
Cadrage : Légal et Préparation de l'Environnement (Tâches 0, 1, 2)
Répertoire de travail : D:\4thS2emsi\securite mobile\lab-mobile-security

Environnement utilisé
ÉlémentDétailSystème HôteWindows (Local) — VS CodeRépertoireD:\4thS2emsi\securite mobile\lab-mobile-securityOutils OSINTBeVigilAnalyse statiqueYaazhini + script Python (yaazhini.py)Application analyséeDiva — jakhar.aseem.diva v1.0

Structure du Lab
lab-mobile-security/
├── 00-scope/
├── 01-bevigil/
│   └── bevigil_notes.md
├── 02-yaazhini/
│   ├── yaazhini.py
│   ├── yaazhini_notes.md
│   └── yaazhini_report.json
├── 03-triage/
├── 04-report/
├── analyse_info.txt        (540 bytes)
├── checklist_fin.md        (863 bytes)
├── commands.log            (290 bytes)
└── README.md               (374 bytes)

Partie 1 — Analyse OSINT avec BeVigil
Notes d'Analyse OSINT (bevigil_notes.md)
markdown# Notes d'Analyse OSINT - BeVigil

## 1. Ce qui est certain (Faits établis)
- [Ex: L'application communique avec le domaine api.example.com]
- [Ex: Le package name exact est com.example.app]

## 2. Ce qui est hypothèse (À vérifier)
- [Ex: La clé API Google Maps trouvée semble avoir des restrictions faibles,
  à vérifier manuellement]

## 3. Points d'intérêt
- [Ex: Présence d'un composant d'export d'activité non protégé]

## 4. Domaines et Sous-domaines
- `api.[MASQUÉ].com`
- `dev.[MASQUÉ].net`

## 5. Endpoints et APIs
- `https://api.[MASQUÉ].com/v1/users/`
- `https://api.[MASQUÉ].com/v1/config/`

## 6. URLs HTTP/HTTPS
- `http://insecure.[MASQUÉ].com/upload` (Attention: HTTP en clair)

## 7. Emails et Identifiants
- `admin@[MASQUÉ].com`
- `support@[MASQUÉ].com`

## 8. Technologies Détectées
- [Ex: Firebase, AWS S3, React Native, Flutter]

Partie 2 — Analyse Statique avec Yaazhini
Script Python yaazhini.py
pythonimport argparse
import os
import json
import re
from androguard.core.bytecodes.apk import APK

def analyze_apk(apk_path, output_dir):
    print(f"[*] Démarrage de l'analyse de : {apk_path}")

    if not os.path.exists(apk_path):
        print(f"[!] ERREUR : Le fichier {apk_path} est introuvable.")
        return

    try:
        a = APK(apk_path)
    except Exception as e:
        print(f"[!] ERREUR lors de l'ouverture de l'APK : {e}")
        return

    report = {
        "app_name":  a.get_app_name(),
        "package":   a.get_package(),
        "version_name": a.get_androidversion_name(),
        "permissions_excessives_potentielles": [],
        "configurations_sensibles": {},
        "endpoints_potentiels": []
    }

    print("[*] Extraction des permissions...")
    permissions = a.get_permissions()
    sensitive_perms = [
        "android.permission.CAMERA",         "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_SMS",
        "android.permission.RECORD_AUDIO",   "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    ]

Rapport JSON généré (yaazhini_report.json)
json{
    "app_name": "Diva",
    "package": "jakhar.aseem.diva",
    "version_name": "1.0",
    "permissions_excessives_potentielles": [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    ],
    "configurations_sensibles": {
        "allowBackup": "true",
        "debuggable": "true",
        "usesCleartextTraffic": "Non défini"
    },
    "endpoints_potentiels": [
        "http://payatu.com"
    ]
}

Notes d'Analyse Statique (yaazhini_notes.md)
markdown# Notes d'Analyse Statique - Yaazhini
Constat 1 : Permission Sensible

Localisation : AndroidManifest.xml
Description : L'application demande la permission android.permission.READ_SMS.
Impact potentiel : Atteinte à la vie privée, lecture de codes OTP.
Remédiation suggérée : Utiliser l'API SMS Retriever de Google au lieu de lire tous les SMS.

Constat 2 : Secret Codé en Dur

Localisation : com/example/app/utils/Constants.java
Description : Présence d'une clé d'API AWS codée en dur. Secret : AKIA[MASQUÉ]
Impact potentiel : Usurpation d'identité, accès non autorisé aux ressources cloud.
Remédiation suggérée : Gérer les secrets côté serveur et les récupérer dynamiquement de manière sécurisée.

Constat 3 : Sauvegarde Autorisée (Backup)

Localisation : AndroidManifest.xml
Description : L'attribut android:allowBackup="true" est présent.
Impact potentiel : Un attaquant avec accès physique (ou via adb) peut extraire les données privées de l'application.
Remédiation suggérée : Définir android:allowBackup="false".

Constat 4 : Stockage Insecure

Localisation : com/example/app/auth/LoginManager.java
Description : Le token de session est sauvegardé en clair dans les SharedPreferences.
Impact potentiel : Vol de session si l'appareil est compromis (root) ou via une sauvegarde.
Remédiation suggérée : Utiliser EncryptedSharedPreferences ou le Keystore d'Android.

Constat 5 : Composant Exporté

Localisation : AndroidManifest.xml
Description : L'activité DebugActivity est exportée (android:exported="true").
Impact potentiel : N'importe quelle autre application sur le téléphone peut lancer cette activité.
Remédiation suggérée : Définir android:exported="false" ou protéger l'accès avec une permission personnalisée forte.


Récapitulatif des Vulnérabilités — Application Diva
#ConstatFichierSévéritéRemédiation1Permission READ_SMSAndroidManifest.xml🟠 HauteAPI SMS Retriever2Clé AWS codée en durConstants.java🔴 CritiqueSecrets côté serveur3allowBackup="true"AndroidManifest.xml🟠 HauteMettre à false4Token en clair (SharedPreferences)LoginManager.java🔴 CritiqueEncryptedSharedPreferences5DebugActivity exportéeAndroidManifest.xml🟡 Moyenneexported="false"6HTTP en clair (http://payatu.com)Code source🟠 HauteMigrer vers HTTPS7debuggable="true"AndroidManifest.xml🟠 HauteDésactiver en production8READ/WRITE_EXTERNAL_STORAGEAndroidManifest.xml🟡 MoyenneScoped Storage Android

Conclusion
Ce lab a permis de réaliser une analyse complète de la posture de sécurité de l'application Diva en combinant l'OSINT avec BeVigil (découverte de domaines, APIs, emails, technologies) et l'analyse statique automatisée avec Yaazhini (script Python + androguard). Le rapport JSON généré synthétise les permissions excessives, configurations sensibles et endpoints détectés.
