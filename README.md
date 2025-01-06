# **SafeBayFS**

SafeBayFS ist ein innovatives, FUSE-basiertes verschlüsseltes Dateisystem, das Datensicherheit und Benutzerfreundlichkeit miteinander verbindet. Durch die Kombination moderner Verschlüsselungstechnologien mit flexibler Linux-Integration bietet SafeBayFS eine robuste Lösung für die sichere Speicherung sensibler Daten.

---

## **🔒 Was ist SafeBayFS?**
SafeBayFS ist ein speziell entwickeltes Dateisystem, das auf **[FUSE (Filesystem in Userspace)](https://github.com/libfuse/libfuse)** basiert. Es ermöglicht die transparente Verschlüsselung und Speicherung von Dateien direkt auf einem Linux-System. Dabei werden zwei fortschrittliche kryptografische Algorithmen verwendet:

- **[POET (Pipelineable Online Encryption with Authenticated Tag)](https://github.com/medsec/poet)**: Gewährleistet eine sichere und performante Verschlüsselung aller gespeicherten Daten.
- **[Catena](https://github.com/medsec/catena)**: Eine robuste Key Derivation Function (KDF), die starke Passwörter generiert, um den Verschlüsselungsschlüssel für POET abzuleiten.

---

## **🔧 Wie funktioniert SafeBayFS?**
SafeBayFS integriert sich nahtlos in das Linux-Dateisystem über FUSE und nutzt folgende Sicherheitsmechanismen:

1. **Verschlüsselung mit POET**:
   - POET verschlüsselt jede Datei auf Blockebene, wodurch selbst große Dateien effizient verarbeitet werden.
   - Jede Datei wird mit einer eindeutigen Nonce (Initialisierungsvektor) und einem kryptografisch sicheren Authentifizierungstag geschützt.

2. **Starke Schlüsselgenerierung mit Catena**:
   - Benutzerpasswörter werden mittels Catena in einen kryptografisch sicheren Schlüssel umgewandelt.
   - Catena bietet zusätzlichen Schutz gegen Brute-Force-Angriffe durch einen zeitintensiven und speichereffizienten Ableitungsprozess.

3. **Transparente Integration**:
   - Benutzer greifen über gewohnte Dateisystem-Operationen wie Lesen und Schreiben auf verschlüsselte Dateien zu.
   - Die Verschlüsselung und Entschlüsselung erfolgen transparent im Hintergrund.

---

## **🌐 Vorteile von SafeBayFS**

- **Maximale Sicherheit**: Kombiniert modernste Verschlüsselung (POET) mit starker Passwort-Ableitung (Catena).
- **Einfache Integration**: Durch die Nutzung von FUSE benötigt SafeBayFS keine tiefgreifenden Systemänderungen.
- **Hohe Performance**: POET ermöglicht eine effiziente Verarbeitung von Dateien ohne merkbare Verzögerungen.
- **Flexibel und portabel**: Funktioniert auf allen Linux-Systemen mit FUSE-Unterstützung.
- **Resistenz gegen Angriffe**: Catena macht das System robust gegen Passwort-basierte Angriffe.

---

## **📚 Einsatzmöglichkeiten**
SafeBayFS eignet sich ideal für:

- **Privatanwender**, die sensible Daten wie Finanzdokumente oder medizinische Unterlagen sichern möchten.
- **Unternehmen**, die Datenkonformität (z. B. DSGVO) sicherstellen müssen.
- **Entwickler**, die eine flexible Verschlüsselungslösung suchen, ohne sich tiefgehend mit Kryptografie auseinanderzusetzen.

---

## **🎯 Ziele von SafeBayFS**

1. **Datensicherheit**: Dateien sollen während der Speicherung und Übertragung sicher verschlüsselt bleiben.
2. **Benutzerfreundlichkeit**: Die Nutzung des Dateisystems soll so einfach sein wie die eines unverschlüsselten Systems.
3. **Flexibilität**: Anpassung an verschiedene Anwendungsfälle durch modulare Architektur.
4. **Skalierbarkeit**: Auch große Datenmengen sollen effizient verarbeitet werden.

---

## **🔨 Technologien hinter SafeBayFS**

- **[FUSE](https://github.com/libfuse/libfuse)**: Ermöglicht die Implementierung von Dateisystemen im Benutzermodus.
- **[POET](https://github.com/medsec/poet)**: Fortschrittlicher Authenticated Encryption Algorithmus, optimiert für Geschwindigkeit und Sicherheit.
- **[Catena](https://github.com/medsec/catena)**: Zeit- und speichereffiziente Key Derivation Function für starke Passwörter.
- **Python und C**: Kombination aus hoher Effizienz und einfacher Erweiterbarkeit.

---

SafeBayFS bietet die perfekte Balance zwischen Sicherheit, Leistung und Benutzerfreundlichkeit und setzt neue Maßstäbe für verschlüsselte Dateisysteme. Probieren Sie SafeBayFS aus und überzeugen Sie sich selbst von seiner Leistungsfähigkeit!

