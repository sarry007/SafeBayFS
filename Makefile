CC = clang

# Basisverzeichnis des Projekts
BASE_DIR := $(CURDIR)

# Dynamische Pfade für SafeBayFS-Verzeichnisse
ROOT_DIR := $(BASE_DIR)/SafeBayFS-ENC
MOUNT_DIR := $(BASE_DIR)/SafeBayFS

# Allgemeine Compiler-Flags
CFLAGS_COMMON = -fomit-frame-pointer -O3 -std=c99 -fgnu89-inline -march=native -s -W -Wall -D_FILE_OFFSET_BITS=64 -maes -msse4.2
CFLAGS_COMMON += -I$(BASE_DIR)/src/poet -I$(BASE_DIR)/src/fuse
CFLAGS_COMMON += -Wno-unused-function -Wno-unused-const-variable
CFLAGS_COMMON += -fstack-protector-all -fsanitize=address -fPIE -D_FORTIFY_SOURCE=2
PKGCONFIG = $(shell pkg-config --cflags --libs fuse)
CFLAGS_COMMON += $(PKGCONFIG)
LDFLAGS_COMMON = -Wl,-z,relro,-z,now -lsodium

# ASAN-spezifische Flags
ASAN_CFLAGS = -fsanitize=address,undefined,leak -fno-omit-frame-pointer -O1 \
              -fstack-protector-strong -D_FORTIFY_SOURCE=2
ASAN_LDFLAGS = -fsanitize=address,undefined,leak -Wl,-z,relro,-z,now

# Catena-spezifische Flags
CATENA_CFLAGS = -fomit-frame-pointer -O3 -std=c99 -fgnu89-inline -march=native -s -W -Wall
CATENA_CFLAGS += -Wno-unused-function -Wno-unused-const-variable

# SSE-Erkennung für Catena
SSE_TAGS = $(shell /bin/grep -m 1 flags /proc/cpuinfo | /bin/grep -o \
	'sse2\|sse3\|ssse3\|sse4a\|sse4.1\|sse4.2' | sed  's/\_/./g')

ifneq ($(SSE_TAGS),)
    # Optimierte Hash-Funktion für SSE
    HDIR = $(BASE_DIR)/src/catena/blake2-sse
    CATENA_CFLAGS += -L$(HDIR) -I$(HDIR)
    HASH = $(HDIR)/blake2b.c
    HASHIMPL = $(BASE_DIR)/src/catena/catena-blake2b-sse.c
else
    # Referenz-Implementierung
    HDIR = $(BASE_DIR)/src/catena/blake2-ref
    CATENA_CFLAGS += -L$(HDIR) -I$(HDIR)
    HASH = $(HDIR)/blake2b-ref.c
    HASHIMPL = $(BASE_DIR)/src/catena/catena-blake2b-ref.c
endif

# Optional: Schnelle und sichere Einstellungen für Catena
ifndef FULLHASH
	CATENA_CFLAGS += -DFAST
endif

ifdef SAFE
    CATENA_CFLAGS += -DOVERWRITE
endif

# Dateien
BASEFILES = $(BASE_DIR)/src/catena/catena.c $(BASE_DIR)/src/catena/catena-helpers.c
FUSE_FILES = $(BASE_DIR)/src/fuse/bbfs.c $(BASE_DIR)/src/fuse/log.c $(BASE_DIR)/src/poet/poet.c $(BASE_DIR)/src/poet/aes.c
FUSE_HEADERS = $(BASE_DIR)/src/fuse/log.h $(BASE_DIR)/src/poet/poet.h $(BASE_DIR)/src/poet/aes.h

.PHONY: check_dependencies create_dirs pam_configuration start_SafeBayFS clean all

# Ziel: Überprüfen der Abhängigkeiten
check_dependencies:
	@echo "Überprüfen der Python3-Installation..."
	@if ! command -v python3 >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y python3; fi
	@echo "Überprüfen der FUSE-Installation..."
	@if ! pkg-config --exists fuse; then sudo apt-get install -y fuse libfuse-dev; fi
	@echo "Überprüfen der libsodium-Installation..."
	@if ! pkg-config --exists libsodium; then sudo apt-get install -y libsodium-dev; fi
	@echo "Abhängigkeiten geprüft."

# Ziel: Verzeichnisse erstellen
create_dirs:
	@echo "Erstelle Verzeichnisse SafeBayFS und SafeBayFS-ENC..."
	@mkdir -p $(ROOT_DIR) $(MOUNT_DIR)
	@echo "Verzeichnisse erstellt."

# Ziel: PAM-Konfiguration
pam_configuration:
	@echo "Konfiguriere PAM..."
	@if ! grep -Fq 'auth optional pam_exec.so' /etc/pam.d/common-auth; then \
		echo 'auth optional pam_exec.so expose_authtok debug /usr/bin/python3 $(BASE_DIR)/pam_SafeBayFS.py' | sudo tee -a /etc/pam.d/common-auth; fi
	@if ! grep -Fq 'session optional pam_exec.so' /etc/pam.d/common-session; then \
		echo 'session optional pam_exec.so seteuid debug /usr/bin/python3 $(BASE_DIR)/pam_SafeBayFS.py' | sudo tee -a /etc/pam.d/common-session; fi

# Ziel: FUSE-Anwendung kompilieren
$(BASE_DIR)/src/fuse/untitled5: $(FUSE_FILES) $(FUSE_HEADERS)
	@echo "Kompiliere FUSE-Anwendung..."
	$(CC) $(CFLAGS_COMMON) $(LDFLAGS_COMMON) -o $@ $(FUSE_FILES)

# Ziel: Catena-Test kompilieren
$(BASE_DIR)/src/catena/catena-Butterfly-blake2b-test:
	@echo "Kompiliere Catena-Test..."
	$(CC) $(CATENA_CFLAGS) -o $@ $(BASE_DIR)/src/catena/test-catena.c $(BASEFILES) $(HASHIMPL) $(BASE_DIR)/src/catena/catena-DBG.c $(HASH)

# Ziel: FUSE-Anwendung mit ASAN
asan_untitled5:
	@echo "Kompiliere FUSE-Anwendung mit AddressSanitizer..."
	$(CC) $(CFLAGS_COMMON) $(ASAN_CFLAGS) $(LDFLAGS_COMMON) $(ASAN_LDFLAGS) -o $(BASE_DIR)/src/fuse/untitled5 $(FUSE_FILES)

# Ziel: Alles mit ASAN (nur für untitled5)
asan: asan_untitled5
	@echo "ASAN-Kompilierung für untitled5 abgeschlossen."


# Ziel: Python-Skript starten
start_SafeBayFS:
	@echo "Starte SafeBayFS..."
	@python3 $(BASE_DIR)/start_SafeBayFS.py || { echo "Fehler beim Start von SafeBayFS."; exit 1; }

# Hauptziel: Alles kompilieren
all: check_dependencies create_dirs pam_configuration \
	$(BASE_DIR)/src/fuse/untitled5 \
	$(BASE_DIR)/src/catena/catena-Butterfly-blake2b-test \
	start_SafeBayFS

# Bereinigung
clean:
	rm -f *~ *.o $(BASE_DIR)/src/catena/catena-Butterfly-blake2b-test $(BASE_DIR)/src/fuse/untitled5
	rm -rf $(ROOT_DIR) $(MOUNT_DIR)

