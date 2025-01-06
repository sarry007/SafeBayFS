SafeBayFS

SafeBayFS ist ein innovatives, FUSE-basiertes verschlüsseltes Dateisystem, das Datensicherheit und Benutzerfreundlichkeit miteinander verbindet. Durch die Kombination moderner Verschlüsselungstechnologien mit flexibler Linux-Integration bietet SafeBayFS eine robuste Lösung für die sichere Speicherung sensibler Daten.

🔒 Was ist SafeBayFS?

SafeBayFS ist ein speziell entwickeltes Dateisystem, das auf FUSE (Filesystem in Userspace) basiert. Es ermöglicht die transparente Verschlüsselung und Speicherung von Dateien direkt auf einem Linux-System. Dabei werden zwei fortschrittliche kryptografische Algorithmen verwendet:

POET (Pipelineable Online Encryption with Authenticated Tag): Gewährleistet eine sichere und performante Verschlüsselung aller gespeicherten Daten.

Catena: Eine robuste Key Derivation Function (KDF), die starke Passwörter generiert, um den Verschlüsselungsschlüssel für POET abzuleiten.

🔧 Wie funktioniert SafeBayFS?

SafeBayFS integriert sich nahtlos in das Linux-Dateisystem über FUSE und nutzt folgende Sicherheitsmechanismen:

Verschlüsselung mit POET:

POET verschlüsselt jede Datei auf Blockebene, wodurch selbst große Dateien effizient verarbeitet werden.

Jede Datei wird mit einer eindeutigen Nonce (Initialisierungsvektor) und einem kryptografisch sicheren Authentifizierungstag geschützt.

Starke Schlüsselgenerierung mit Catena:

Benutzerpasswörter werden mittels Catena in einen kryptografisch sicheren Schlüssel umgewandelt.

Catena bietet zusätzlichen Schutz gegen Brute-Force-Angriffe durch einen zeitintensiven und speichereffizienten Ableitungsprozess.

Transparente Integration:

Benutzer greifen über gewohnte Dateisystem-Operationen wie Lesen und Schreiben auf verschlüsselte Dateien zu.

Die Verschlüsselung und Entschlüsselung erfolgen transparent im Hintergrund.

🌐 Vorteile von SafeBayFS

Maximale Sicherheit: Kombiniert modernste Verschlüsselung (POET) mit starker Passwort-Ableitung (Catena).

Einfache Integration: Durch die Nutzung von FUSE benötigt SafeBayFS keine tiefgreifenden Systemänderungen.

Hohe Performance: POET ermöglicht eine effiziente Verarbeitung von Dateien ohne merkbare Verzögerungen.

Flexibel und portabel: Funktioniert auf allen Linux-Systemen mit FUSE-Unterstützung.

Resistenz gegen Angriffe: Catena macht das System robust gegen Passwort-basierte Angriffe.

📚 Einsatzmöglichkeiten

SafeBayFS eignet sich ideal für:

Privatanwender, die sensible Daten wie Finanzdokumente oder medizinische Unterlagen sichern möchten.

Unternehmen, die Datenkonformität (z. B. DSGVO) sicherstellen müssen.

Entwickler, die eine flexible Verschlüsselungslösung suchen, ohne sich tiefgehend mit Kryptografie auseinanderzusetzen.

🎯 Ziele von SafeBayFS

Datensicherheit: Dateien sollen während der Speicherung und Übertragung sicher verschlüsselt bleiben.

Benutzerfreundlichkeit: Die Nutzung des Dateisystems soll so einfach sein wie die eines unverschlüsselten Systems.

Flexibilität: Anpassung an verschiedene Anwendungsfälle durch modulare Architektur.

Skalierbarkeit: Auch große Datenmengen sollen effizient verarbeitet werden.

🔨 Technologien hinter SafeBayFS

FUSE: Ermöglicht die Implementierung von Dateisystemen im Benutzermodus.

POET: Fortschrittlicher Authenticated Encryption Algorithmus, optimiert für Geschwindigkeit und Sicherheit.

Catena: Zeit- und speichereffiziente Key Derivation Function für starke Passwörter.

Python und C: Kombination aus hoher Effizienz und einfacher Erweiterbarkeit.