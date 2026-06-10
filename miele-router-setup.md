# Appairage Miele@home — diagnostic routeur Synology

Document de contexte pour la personne qui prendra la main en SSH sur mon routeur Synology. But : faire appairer un électroménager Miele (Miele@home / Miele@mobile) au Wi‑Fi domestique. Je suis convaincu que le routeur Synology est le point de blocage.

## Contexte matériel

- **Routeur** : Synology (SRM)
- **Appareil à appairer** : électroménager Miele compatible Miele@home
- **Application** : Miele app (iOS / Android)
- **Symptôme** : impossible de finaliser l'appairage de l'appareil Miele au réseau Wi‑Fi

## Contraintes connues côté Miele

- L'appareil **ne fonctionne qu'en 2,4 GHz**, pas de 5 GHz.
- Sécurité **WPA2-Personal** uniquement. Pas de WPA3, pas de mixte WPA2/WPA3.
- L'appairage utilise du **mDNS / Bonjour (multicast)** entre le téléphone et l'appareil.
- Pendant le setup, l'appareil Miele crée son propre AP temporaire (SSID type `Miele@home-xxxx`) auquel le téléphone doit pouvoir se connecter, puis les credentials Wi‑Fi sont poussés vers l'appareil.

## Ce qui a déjà été tenté côté routeur Synology (sans succès)

Tous les réglages ci‑dessous ont été modifiés via l'interface SRM. À chaque modification, j'ai relancé la procédure d'appairage depuis zéro (reset Miele + reconnexion téléphone en 2,4 GHz). Aucun n'a permis l'appairage.

### 1. SSID 2,4 GHz dédié

- Désactivation de **Smart Connect** (les bandes 2,4 et 5 GHz ne partagent plus le même SSID).
- Création d'un SSID **séparé pour le 2,4 GHz**.
- Téléphone forcé sur le SSID 2,4 GHz pendant tout le setup, données mobiles coupées.
- **Résultat** : pas d'amélioration.

### 2. Sécurité Wi‑Fi

- Passage en **WPA2-Personal uniquement** sur le SSID 2,4 GHz (pas WPA3, pas mixte).
- **Résultat** : pas d'amélioration.

### 3. Mode et largeur de canal 2,4 GHz

- Mode radio fixé sur **b/g/n** (pas `n only`, pas `ax only`).
- Largeur de canal **20 MHz**.
- Canal fixé manuellement sur **1, 6 ou 11** (testé les trois, pas d'auto).
- **Résultat** : pas d'amélioration.

### 4. Isolation client / AP isolation

- Désactivation de **AP Isolation** / **Client Isolation** sur le SSID 2,4 GHz.
- Le téléphone et l'appareil Miele sont sur le **même réseau / même VLAN** (LAN principal, pas de réseau invité, pas de VLAN IoT séparé).
- **Résultat** : pas d'amélioration.

### 5. Filtrages applicatifs

- **Safe Access** : téléphone temporairement en profil "Aucun filtre".
- **Threat Prevention** : désactivé pendant l'appairage.
- **Filtrage MAC** : désactivé.
- **Résultat** : pas d'amélioration.

### 6. Multicast / mDNS

- Testé **IGMP Snooping activé** puis **désactivé** (Centre réseau > Réseau local > Général).
- **Résultat** : pas d'amélioration dans les deux cas.

### 7. DHCP / pare‑feu

- Vérifié qu'il reste des baux DHCP disponibles.
- Pare‑feu : pas de règle bloquant le trafic LAN→LAN.
- **Résultat** : pas d'amélioration.

## Procédure d'appairage utilisée (à chaque test)

1. Téléphone connecté **en 2,4 GHz** sur le SSID dédié, données mobiles désactivées.
2. Reset Wi‑Fi sur l'appareil Miele jusqu'à voyant Wi‑Fi clignotant (mode setup actif, AP `Miele@home-xxxx` visible).
3. App Miele > Ajouter un appareil.
4. iOS demande de rejoindre manuellement le SSID `Miele@home-xxxx` → fait.
5. Retour dans l'app → l'app pousse les credentials Wi‑Fi vers l'appareil.
6. L'appareil devrait rejoindre le SSID 2,4 GHz du domicile et l'app devrait finaliser.

**Étape qui plante** : à confirmer / préciser (à remplir au moment de la démo en live).

## Pistes restantes à explorer côté Synology

À tenter en SSH / via SRM :

- Vérifier en `tcpdump` / `tshark` sur l'interface du LAN ce qui transite réellement pendant l'appairage (mDNS `_miele._tcp` / `_http._tcp`, requêtes DHCP de l'appareil Miele, ARP).
- Vérifier les logs SRM (`/var/log/messages`, logs du firewall, logs hostapd) au moment précis de la tentative.
- Confirmer que l'appareil Miele obtient bien un bail DHCP (table des baux SRM + ARP).
- Vérifier l'éventuel **rate limiting** / protection broadcast/multicast au niveau hostapd.
- Tester en désactivant temporairement le pare‑feu SRM en entier.
- Tester en mettant le SSID 2,4 GHz en **réseau totalement à plat** (pas de QoS, pas de Traffic Control, pas de protections supplémentaires).
- Vérifier la version du firmware SRM ; si récente, regarder le changelog pour des régressions multicast/mDNS.
- En dernier recours : connecter un AP/hotspot externe (téléphone ou autre routeur en mode AP) pour confirmer que l'appareil Miele s'appaire correctement hors Synology — et donc isoler la responsabilité du routeur.

## Accès fourni

- SSH ouvert sur le routeur Synology (compte admin).
- Accès SRM UI possible sur demande.
- Je suis joignable en direct pendant les tests pour relancer la procédure d'appairage côté téléphone + appareil Miele à la demande.
