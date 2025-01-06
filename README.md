-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SafeBayFS - FUSE-verschlüsseltes Dateisystem Übersicht
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SafeBayFS ist ein FUSE-basiertes verschlüsseltes Dateisystem, das mithilfe des POET- und Catena-Algorithmus Daten sicher speichert. Dieses Projekt enthält ein Makefile, das die notwendigen Abhängigkeiten installiert, die Projektdateien kompiliert und die PAM-Konfiguration anpasst, um das Passwort des Benutzers sicher zu handhaben.

bbfs.c: Beinhaltet die grundlegende FUSE-Integration und die spezifischen Anpassungen zur Nutzung von POET für Dateioperationen wie Lesen, Schreiben und Verschlüsselung.
Alle Codeabschnitte in bbfs.c sind mit //Master gekennzeichnet.

catena-test.c: Enthält die Implementierung der Catena Key Derivation Function (KDF), die zur sicheren Ableitung kryptografischer Schlüssel verwendet wird.

Python-Skripte (start_SafeBayFS.py): Diese Skripte steuern den sicheren Start von SafeBayFS, 
einschließlich der Authentifizierung über PAM, der Nutzung von Catena zur Schlüsselgenerierung und der anschließenden Übergabe an das FUSE-System.

Python-Skripte (pam_SafeBayFS.py): Dieses Skript startet SafaBayFS nach der Erstanmeldung auf dem System.  


Voraussetzungen
Bevor Sie SafeBayFS verwenden, stellen Sie sicher, dass Ihr System folgende Voraussetzungen erfüllt:

Systemvoraussetzungen:

Betriebssystem: Ubuntu oder ein vergleichbares Linux-System.
Paketmanager: apt muss verfügbar sein.
Installierte Software:

Python 3
pip für Python 3
FUSE (Filesystem in Userspace)
libsodium (für kryptografische Funktionen)
Funktionen des Makefiles
Ziele
Das Makefile bietet folgende Ziele:

Abhängigkeiten überprüfen und installieren:
Installiert Python, pip, FUSE und libsodium, falls diese nicht vorhanden sind.
PAM-Konfiguration anpassen:
Konfiguriert common-auth und common-session, um das Passwort an das Python-Skript weiterzugeben.
Projekt kompilieren:
Kompiliert die Catena.
Kompiliert das FUSE-Programm.


Verzeichnisse erstellen:
Erstellt die notwendigen Verzeichnisse für das verschlüsselte Dateisystem.
Python-Skript ausführen:
Startet das Python-Skript, um das verschlüsselte Dateisystem zu montieren.


Verwendung

Makefile-Ziele
Führen Sie die folgenden Befehle aus, um das Projekt zu erstellen und zu konfigurieren:


Alle Abhängigkeiten installieren und das Projekt kompilieren:
make all

Verzeichnisse erstellen:
make create_dirs

Projekt bereinigen:
make clean

FUSE-Programm starten:
make run_python_script

PAM-Konfiguration
Das Makefile passt die PAM-Konfiguration automatisch an. Folgende Einstellungen werden hinzugefügt:

common-auth: auth optional pam_exec.so expose_authtok debug /usr/bin/python3 <PFAD_ZUM_SKRIPT> >> /tmp/pam_exec_auth.log 2>&1


common-session: 
session optional pam_exec.so seteuid debug /usr/bin/python3 <PFAD_ZUM_SKRIPT> >> /tmp/pam_exec_session.log 2>&1

Diese Einstellungen sorgen dafür, dass das Passwort sicher vom PAM-Modul an das Python-Skript übergeben wird.



Fehlerbehebung
Fehler beim Verknüpfen (undefined reference to 'fuse_get_context'):

Stellen Sie sicher, dass libfuse-dev installiert ist:
sudo apt-get install libfuse-dev


PAM-Konfiguration nicht angewendet:

Prüfen Sie die Dateien /etc/pam.d/common-auth und /etc/pam.d/common-session, ob die Einträge vorhanden sind.
Stellen Sie sicher, dass das Python-Skript unter dem angegebenen Pfad existiert.


FUSE-Programm startet nicht:

Überprüfen Sie die Log-Dateien:
/tmp/pam_exec_auth.log
/tmp/pam_exec_session.log

