# SafeBayFS - FUSE-verschlüsseltes Dateisystem

SafeBayFS ist ein FUSE-basiertes verschlüsseltes Dateisystem, das mithilfe der **POET**- und **Catena**-Algorithmen Daten sicher speichert. Dieses Projekt bietet eine robuste Lösung zur Verschlüsselung von Dateisystemen mit Funktionen wie benutzerdefinierter Schlüsselableitung und sicherer Passwortverarbeitung.

---

## 📂 Projektübersicht


- **`bbfs.c`**: 
  - Beinhaltet die grundlegende FUSE-Integration und spezifische Anpassungen zur Nutzung von POET für Dateioperationen (Lesen, Schreiben, Verschlüsselung).
  - Alle relevanten Codeabschnitte sind mit `//Master` gekennzeichnet.
  
- **`catena-test.c`**: 
  - Implementiert die Catena Key Derivation Function (KDF), die zur sicheren Ableitung kryptografischer Schlüssel verwendet wird.
  
- **Python-Skripte**:
  - **`start_SafeBayFS.py`**: Steuert den Start von SafeBayFS, einschließlich der Authentifizierung über PAM, Schlüsselgenerierung mit Catena und Übergabe an das FUSE-System.
  - **`pam_SafeBayFS.py`**: Startet SafeBayFS nach der Erstanmeldung des Benutzers im System.

---

## 📋 Voraussetzungen

### Systemvoraussetzungen:
- **Betriebssystem**: Ubuntu oder ein vergleichbares Linux-System
- **Paketmanager**: `apt` muss verfügbar sein

### Software-Abhängigkeiten:
- Python 3
- `pip` für Python 3
- FUSE (Filesystem in Userspace)
- Libsodium (für kryptografische Funktionen)

---

## 🛠 Funktionen des Makefiles

Das **Makefile** bietet verschiedene Ziele zur Automatisierung der Installation, Konfiguration und Ausführung:

### **Hauptziele:**
1. **Abhängigkeiten installieren**:
   - Überprüft und installiert Python, pip, FUSE und libsodium, falls diese nicht vorhanden sind.
   
2. **PAM-Konfiguration anpassen**:
   - Konfiguriert `common-auth` und `common-session`, um das Benutzerpasswort sicher an das Python-Skript weiterzugeben.

3. **Projekt kompilieren**:
   - Kompiliert die Catena-Implementierung und das FUSE-Programm.

4. **Verzeichnisse erstellen**:
   - Erstellt die notwendigen Verzeichnisse für das verschlüsselte Dateisystem.

5. **Python-Skript ausführen**:
   - Startet das Python-Skript, um das verschlüsselte Dateisystem zu montieren.

---

## 🚀 Verwendung

### **Makefile-Befehle**:
Führen Sie die folgenden Befehle aus, um das Projekt zu erstellen und zu konfigurieren:

- **Alle Abhängigkeiten installieren und das Projekt kompilieren:**
  ```bash
  make all
