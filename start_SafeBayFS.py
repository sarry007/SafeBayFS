import getpass
import subprocess
import os
from pam import pam

def authenticate_user(username, password):
    """
    Authentifiziert den Benutzer mithilfe von PAM.
    """
    pam_auth = pam()
    try:
        if pam_auth.authenticate(username, password):
            print("DEBUG: Authentifizierung erfolgreich.")
            return True
        else:
            print("DEBUG: Authentifizierung fehlgeschlagen.")
            return False
    except Exception as e:
        print(f"DEBUG: Fehler bei der Authentifizierung: {e}")
        return False

def xor_hex_strings(hex_str1, hex_str2):
    """
    Führt ein XOR zwischen zwei hexadezimalen Strings durch.
    """
    int1 = int(hex_str1, 16)
    int2 = int(hex_str2, 16)
    xor_result = int1 ^ int2
    return f'{xor_result:0{len(hex_str1)}x}'

def process_catena_hash_multiple_times(hex_str, rounds=2):
    """
    Verarbeitet den Catena-Hash mehrmals mit XOR.
    """
    current_hash = hex_str
    for i in range(rounds):
        half_len = len(current_hash) // 2
        first_half = current_hash[:half_len]
        second_half = current_hash[half_len:]
        current_hash = xor_hex_strings(first_half, second_half)
        print(f"DEBUG: Zwischenergebnis nach XOR-Runde {i + 1}: {current_hash}")
    return current_hash

def run_catena(password, catena_program):
    """
    Führt das Catena-Programm aus, übergibt das Passwort und wartet auf die Ausgabe.
    """
    print("DEBUG: Starte Catena-Programm...")
    try:
        result = subprocess.run(
            [catena_program, password],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            print(f"DEBUG: Fehler bei der Catena-Ausführung: {result.stderr}")
            return None
        print(f"DEBUG: Catena-Programm erfolgreich beendet. Ausgabe: {result.stdout}")
        return result.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        print("DEBUG: Catena-Programm hat zu lange gebraucht.")
        return None
    except Exception as e:
        print(f"DEBUG: Unerwarteter Fehler bei Catena: {e}")
        return None

def extract_hash_from_catena_output(output_lines):
    """
    Extrahiert den gültigen Hash aus der Catena-Ausgabe.
    """
    for line in output_lines:
        if all(c in "0123456789abcdefABCDEF" for c in line):
            print(f"DEBUG: Gültiger Catena-Hash gefunden: {line}")
            return line
    print("DEBUG: Kein gültiger Hash in der Catena-Ausgabe gefunden.")
    return None

def start_safe_bay_fs(fuse_program, rootdir, mountdir, final_key):
    """
    Startet SafeBayFS und übergibt den finalen Schlüssel.
    """
    print("DEBUG: Starte SafeBayFS...")
    try:
        bbfs_process = subprocess.Popen(
            [fuse_program, rootdir, mountdir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Schlüssel übergeben
        print(f"DEBUG: Übergebe finalen Schlüssel: {final_key}")
        bbfs_process.stdin.write(f"{final_key}\n")
        bbfs_process.stdin.flush()

        # Warte auf SafeBayFS
        stdout, stderr = bbfs_process.communicate(timeout=30)
        print(f"DEBUG: SafeBayFS beendet. Ausgabe: {stdout}, Fehler: {stderr}")

        if bbfs_process.returncode == 0:
            print("SafeBayFS erfolgreich gestartet.")
        else:
            print("Fehler bei der Ausführung von SafeBayFS.")
    except BrokenPipeError:
        print("DEBUG: SafeBayFS hat die Eingabe unerwartet beendet.")
    except subprocess.TimeoutExpired:
        print("DEBUG: SafeBayFS hat nicht rechtzeitig geantwortet.")
    except Exception as e:
        print(f"DEBUG: Unerwarteter Fehler mit SafeBayFS: {e}")

# Dynamische Pfade
current_dir = os.path.dirname(os.path.abspath(__file__))
catena_program = os.path.join(current_dir, "src/catena/catena-Butterfly-blake2b-test")
rootdir = os.path.join(current_dir, "SafeBayFS-ENC")
mountdir = os.path.join(current_dir, "SafeBayFS")
fuse_program = os.path.join(current_dir, "src/fuse/untitled5")

print(f"DEBUG: Verzeichnisse:\n  Catena: {catena_program}\n  Rootdir: {rootdir}\n  Mountdir: {mountdir}\n  Fuse: {fuse_program}")

# Benutzerdaten
username = input("Benutzername: ")
password = getpass.getpass('Passwort:')

if authenticate_user(username, password):
    # Passwort an Catena weiterleiten
    catena_output = run_catena(password, catena_program)
    if catena_output is None:
        print("Fehler bei der Ausführung von Catena. Programm wird beendet.")
        exit(1)

    # Hash extrahieren
    catena_hash = extract_hash_from_catena_output(catena_output)
    if catena_hash is None:
        print("Kein gültiger Hash gefunden. Programm wird beendet.")
        exit(1)

    # Finalen Schlüssel berechnen
    final_key = process_catena_hash_multiple_times(catena_hash, rounds=2)
    print(f"DEBUG: Finaler Schlüssel: {final_key}")

    # Verzeichnisse erstellen
    print("DEBUG: Erstelle Verzeichnisse...")
    subprocess.run(["mkdir", "-p", rootdir, mountdir])
    if not os.path.exists(rootdir) or not os.path.exists(mountdir):
        print(f"Fehler: Verzeichnisse {rootdir} oder {mountdir} wurden nicht erstellt.")
        exit(1)

    # Finalen Schlüssel an SafeBayFS weitergeben
    start_safe_bay_fs(fuse_program, rootdir, mountdir, final_key)
else:
    print("Authentifizierung fehlgeschlagen. Programm wird beendet.")

