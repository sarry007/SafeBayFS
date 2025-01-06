#!/usr/bin/env python3

import sys
import subprocess
import os
import time

# Pfad zur Logdatei im Verzeichnis des Python-Skripts
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safebayfs.log")

def log_message(message):
    """Schreibt eine Nachricht in die Log-Datei."""
    try:
        with open(log_file, "a") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    except Exception as e:
        print(f"Fehler beim Schreiben in die Log-Datei: {e}")

# Rechte ändern (vorher explizit UID und GID setzen)
USER_UID = 1000  # UID des Benutzers
USER_GID = 1000  # GID des Benutzers

try:
    os.setgid(USER_GID)
    os.setuid(USER_UID)
    log_message(f"Rechte geändert: UID={os.getuid()}, GID={os.getgid()}")
except PermissionError as e:
    log_message(f"Fehler beim Setzen der Rechte: {e}")
    sys.exit(1)

# Umgebungsvariablen anpassen
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{USER_UID}"
os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{USER_UID}/bus"

log_message(f"Umgebungsvariablen: {os.environ}")

def xor_hex_strings(hex_str1, hex_str2):
    """Führt eine XOR-Operation zwischen zwei Hex-Strings durch."""
    int1 = int(hex_str1, 16)
    int2 = int(hex_str2, 16)
    xor_result = int1 ^ int2
    return f'{xor_result:x}'.zfill(len(hex_str1))

def process_catena_hash_multiple_times(hex_str, rounds=2):
    """Verarbeitet einen Catena-Hash mehrmals mit XOR-Operationen."""
    current_hash = hex_str
    for i in range(rounds):
        half_len = len(current_hash) // 2
        first_half = current_hash[:half_len]
        second_half = current_hash[half_len:]
        current_hash = xor_hex_strings(first_half, second_half)
        log_message(f"Zwischenergebnis nach XOR-Runde {i + 1}: {current_hash}")
    return current_hash

# Ermittlung des aktuellen Skript-Verzeichnisses
current_dir = os.path.dirname(os.path.abspath(__file__))

# Dynamische Pfaddefinition mit neuen Verzeichnisnamen
catena_program = os.path.join(current_dir, "src/catena/catena-Butterfly-blake2b-test")
rootdir = os.path.join(current_dir, "SafeBayFS-ENC")
mountdir = os.path.join(current_dir, "SafeBayFS")
fuse_program = os.path.join(current_dir, "src/fuse/untitled5")

# Passwort aus stdin lesen
try:
    password = sys.stdin.read().strip()
except Exception as e:
    log_message(f"Fehler beim Lesen von stdin: {e}")
    sys.exit(1)

if not password:
    log_message("Kein Passwort erhalten. Skript wird beendet.")
    sys.exit(1)

log_message(f"Passwort erhalten (Länge: {len(password)})")

# Führe Catena-Programm aus
try:
    result = subprocess.run([catena_program, password], capture_output=True, text=True)
    if result.returncode == 0:
        output_lines = result.stdout.strip().splitlines()
        for line in output_lines:
            if all(c in "0123456789abcdefABCDEF" for c in line):
                catena_hash = line
                break
        else:
            log_message("Kein gültiger Hash in der Ausgabe gefunden.")
            sys.exit(1)

        log_message(f"Catena Hash: {catena_hash}")
        final_key = process_catena_hash_multiple_times(catena_hash, rounds=2)
        log_message(f"Finaler Schlüssel nach XOR-Verarbeitung: {final_key}")
    else:
        log_message(f"Fehler bei der Ausführung von Catena: {result.stderr}")
        sys.exit(1)
except Exception as e:
    log_message(f"Fehler beim Ausführen von Catena: {e}")
    sys.exit(1)

# Verzeichnisse überprüfen
log_message("Überprüfe Verzeichnisse für SafeBayFS...")
if not os.path.exists(mountdir):
    log_message(f"Mount-Verzeichnis {mountdir} existiert nicht, wird erstellt.")
    os.makedirs(mountdir, exist_ok=True)

# Starte SafeBayFS
try:
    bbfs_process = subprocess.Popen(
        [fuse_program, rootdir, mountdir],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    log_message("SafeBayFS erfolgreich gestartet.")

    # Erste Eingabe: Schlüssel und Enter
    bbfs_process.stdin.write(f"{final_key}\n")
    bbfs_process.stdin.flush()
    log_message("Schlüssel erfolgreich übergeben.")

    # Zweite Eingabe: Nur Enter
    bbfs_process.stdin.write("\n")
    bbfs_process.stdin.flush()
    log_message("Eingabe abgeschlossen. Warte auf Prozess.")

    # Warten auf Prozessabschluss
    return_code = bbfs_process.wait()

    # Erfassen der Ausgaben von STDOUT und STDERR
    log_message(f"SafeBayFS-STDOUT: {bbfs_process.stdout.read()}")
    log_message(f"SafeBayFS-STDERR: {bbfs_process.stderr.read()}")

    log_message(f"SafeBayFS beendet mit Rückgabewert: {return_code}")

    if return_code != 0:
        log_message("SafeBayFS konnte nicht erfolgreich gestartet werden.")
        sys.exit(1)
    else:
        log_message("SafeBayFS erfolgreich gestartet.")
except BrokenPipeError as e:
    log_message(f"BrokenPipeError: {e}")
    sys.exit(1)
except Exception as e:
    log_message(f"Unerwarteter Fehler: {e}")
    sys.exit(1)

