



/*

Der gnaze FUSE Code wurde aus dem Projekt https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/src/bbfs.c übernommen
und mit der modernen Verschlüsselungsmethode POET kombiniert.

Weitre Qullen:
POET: https://github.com/medsec/poet/tree/master
Catena: https://github.com/medsec/catena
*/



/*
  Big Brother File System
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  This code is derived from function prototypes found /usr/include/fuse/fuse.h
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  His code is licensed under the LGPLv2.
  A copy of that code is included in the file fuse.h

  The point of this FUSE filesystem is to provide an introduction to
  FUSE.  It was my first FUSE filesystem as I got to know the
  software; hopefully, the comments in this code will help people who
  follow later to get a gentler introduction.

  This might be called a no-op filesystem:  it doesn't impose
  filesystem semantics on top of any other existing structure.  It
  simply reports the requests that come in, and passes them to an
  underlying filesystem.  The information is saved in a logfile named
  bbfs.log, in the directory from which you run bbfs.
*/
#include "config.h"
#include "params.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <unistd.h>
#include <sys/types.h>
#include <sodium.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif
#include <sys/random.h>  // Für getrandom
#include "log.h"
#include  "/home/uni/CLionProjects/untitled5/poet_vorleseung/poet.h"
#include  "/home/uni/CLionProjects/untitled5/poet_vorleseung/aes.h"

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.

//Master
#define CRYPTO_KEYBYTES 16     // Schlüsselgröße auf 16 Bytes begrenzen
#define KEY_LEN_HEX 32         // Schlüssel als 32 Hex-Zeichen
#define MAX_ARG_LENGTH 1028    // Maximale Länge für rootDir und mountPoint
#define BUFFER_SIZE 4096
#define NONCE_LEN 16
#define HEADER_LEN 16



static void bb_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, BB_DATA->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
				    // break here

    log_msg("    bb_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
	    BB_DATA->rootdir, path, fpath);
}

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int bb_getattr(const char *path, struct stat *statbuf)
{
    int retstat;
    char fpath[PATH_MAX];

    log_msg("\nbb_getattr(path=\"%s\", statbuf=0x%08x)\n",
	  path, statbuf);
    bb_fullpath(fpath, path);

    retstat = log_syscall("lstat", lstat(fpath, statbuf), 0);

    log_stat(statbuf);

    return retstat;
}

/** Read the target of a symbolic link
 *
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
// Note the system readlink() will truncate and lose the terminating
// null.  So, the size passed to to the system readlink() must be one
// less than the size passed to bb_readlink()
// bb_readlink() code by Bernardo F Costa (thanks!)
int bb_readlink(const char *path, char *link, size_t size)
{
    int retstat;
    char fpath[PATH_MAX];

    log_msg("\nbb_readlink(path=\"%s\", link=\"%s\", size=%d)\n",
	  path, link, size);
    bb_fullpath(fpath, path);

    retstat = log_syscall("readlink", readlink(fpath, link, size - 1), 0);
    if (retstat >= 0) {
	link[retstat] = '\0';
	retstat = 0;
	log_msg("    link=\"%s\"\n", link);
    }

    return retstat;
}

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?
int bb_mknod(const char *path, mode_t mode, dev_t dev)
{
    int retstat;
    char fpath[PATH_MAX];

    log_msg("\nbb_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n",
	  path, mode, dev);
    bb_fullpath(fpath, path);

    // On Linux this could just be 'mknod(path, mode, dev)' but this
    // tries to be be more portable by honoring the quote in the Linux
    // mknod man page stating the only portable use of mknod() is to
    // make a fifo, but saying it should never actually be used for
    // that.
    if (S_ISREG(mode)) {
	retstat = log_syscall("open", open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode), 0);
	if (retstat >= 0)
	    retstat = log_syscall("close", close(retstat), 0);
    } else
	if (S_ISFIFO(mode))
	    retstat = log_syscall("mkfifo", mkfifo(fpath, mode), 0);
	else
	    retstat = log_syscall("mknod", mknod(fpath, mode, dev), 0);

    return retstat;
}

/** Create a directory */
int bb_mkdir(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_mkdir(path=\"%s\", mode=0%3o)\n",
	    path, mode);
    bb_fullpath(fpath, path);

    return log_syscall("mkdir", mkdir(fpath, mode), 0);
}

/** Remove a file */
int bb_unlink(const char *path)
{
    char fpath[PATH_MAX];

    log_msg("bb_unlink(path=\"%s\")\n",
	    path);
    bb_fullpath(fpath, path);

    return log_syscall("unlink", unlink(fpath), 0);
}

/** Remove a directory */
int bb_rmdir(const char *path)
{
    char fpath[PATH_MAX];

    log_msg("bb_rmdir(path=\"%s\")\n",
	    path);
    bb_fullpath(fpath, path);

    return log_syscall("rmdir", rmdir(fpath), 0);
}

/** Create a symbolic link */
// The parameters here are a little bit confusing, but do correspond
// to the symlink() system call.  The 'path' is where the link points,
// while the 'link' is the link itself.  So we need to leave the path
// unaltered, but insert the link into the mounted directory.
int bb_symlink(const char *path, const char *link)
{
    char flink[PATH_MAX];

    log_msg("\nbb_symlink(path=\"%s\", link=\"%s\")\n",
	    path, link);
    bb_fullpath(flink, link);

    return log_syscall("symlink", symlink(path, flink), 0);
}

/** Rename a file */
// both path and newpath are fs-relative
int bb_rename(const char *path, const char *newpath)
{
    char fpath[PATH_MAX];
    char fnewpath[PATH_MAX];

    log_msg("\nbb_rename(fpath=\"%s\", newpath=\"%s\")\n",
	    path, newpath);
    bb_fullpath(fpath, path);
    bb_fullpath(fnewpath, newpath);

    return log_syscall("rename", rename(fpath, fnewpath), 0);
}

/** Create a hard link to a file */
int bb_link(const char *path, const char *newpath)
{
    char fpath[PATH_MAX], fnewpath[PATH_MAX];

    log_msg("\nbb_link(path=\"%s\", newpath=\"%s\")\n",
	    path, newpath);
    bb_fullpath(fpath, path);
    bb_fullpath(fnewpath, newpath);

    return log_syscall("link", link(fpath, fnewpath), 0);
}

/** Change the permission bits of a file */
int bb_chmod(const char *path, mode_t mode)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_chmod(fpath=\"%s\", mode=0%03o)\n",
	    path, mode);
    bb_fullpath(fpath, path);

    return log_syscall("chmod", chmod(fpath, mode), 0);
}

/** Change the owner and group of a file */
int bb_chown(const char *path, uid_t uid, gid_t gid)

{
    char fpath[PATH_MAX];

    log_msg("\nbb_chown(path=\"%s\", uid=%d, gid=%d)\n",
	    path, uid, gid);
    bb_fullpath(fpath, path);

    return log_syscall("chown", chown(fpath, uid, gid), 0);
}

/** Change the size of a file */
int bb_truncate(const char *path, off_t newsize)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_truncate(path=\"%s\", newsize=%lld)\n",
	    path, newsize);
    bb_fullpath(fpath, path);

    return log_syscall("truncate", truncate(fpath, newsize), 0);
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
int bb_utime(const char *path, struct utimbuf *ubuf)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_utime(path=\"%s\", ubuf=0x%08x)\n",
	    path, ubuf);
    bb_fullpath(fpath, path);

    return log_syscall("utime", utime(fpath, ubuf), 0);
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */

//MASTER
// Funktion zum Konvertieren eines Byte-Arrays in eine Hex-Zeichenkette
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_str, size_t hex_str_size) {
    if (hex_str_size < (len * 2 + 1)) { // +1 für den Nullterminator
        // Nicht genug Platz, setze Hex-Struktur auf leeren String
        hex_str[0] = '\0';
        return;
    }

    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0'; // Nullterminator
}


// Funktion zum Protokollieren des poet_ctx_t
void log_ctx(const poet_ctx_t *ctx, const char *stage) {
    char hex_buffer[sizeof(block) * 2 + 1]; // 16 Bytes -> 32 Hex-Zeichen + Nullterminator

    log_msg("----- Kontext bei %s -----\n", stage);

    // Nachrichtlänge
    log_msg("mlen: %llu bits\n", (unsigned long long)ctx->mlen);

    // Ausgabe von Block-k
    bytes_to_hex(ctx->k, sizeof(ctx->k), hex_buffer, sizeof(hex_buffer));
    log_msg("k: %s\n", hex_buffer);

    // Ausgabe von Block-l
    bytes_to_hex(ctx->l, sizeof(ctx->l), hex_buffer, sizeof(hex_buffer));
    log_msg("l: %s\n", hex_buffer);

    // Ausgabe von Block-k_axu
    bytes_to_hex(ctx->k_axu, sizeof(ctx->k_axu), hex_buffer, sizeof(hex_buffer));
    log_msg("k_axu: %s\n", hex_buffer);

    // Ausgabe von Block-x
    bytes_to_hex(ctx->x, sizeof(ctx->x), hex_buffer, sizeof(hex_buffer));
    log_msg("x: %s\n", hex_buffer);

    // Ausgabe von Block-y
    bytes_to_hex(ctx->y, sizeof(ctx->y), hex_buffer, sizeof(hex_buffer));
    log_msg("y: %s\n", hex_buffer);

    // Ausgabe von Block-tau
    bytes_to_hex(ctx->tau, sizeof(ctx->tau), hex_buffer, sizeof(hex_buffer));
    log_msg("tau: %s\n", hex_buffer);

    log_msg("----- Ende des Kontexts -----\n\n");
}
//MASTER




int bb_open(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;
    int fd;
    char fpath[PATH_MAX];

    log_msg("\nbb_open(path\"%s\", fi=0x%08x)\n",
        path, fi);
    bb_fullpath(fpath, path);

    // if the open call succeeds, my retstat is the file descriptor,
    // else it's -errno.  I'm making sure that in that case the saved
    // file descriptor is exactly -1.
    fd = log_syscall("open", open(fpath, fi->flags), 0);
    if (fd < 0)
        retstat = log_error("open");

    fi->fh = fd;

    log_fi(fi);

    return retstat;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.


/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */

// ---------------------------------------------------------------------
//MASTER
int bb_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    poet_ctx_t ctx;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted_buffer[BUFFER_SIZE];
    unsigned char tag[TAGLEN];
    unsigned char nonce[NONCE_LEN];
    size_t total_bytes_read = 0;
    off_t encrypted_file_size;
    off_t decrypted_file_size;
    int start_block, end_block;
    size_t offset_in_first_block;
    off_t current_pos;
    int block;

    log_msg("\nbb_read(path=\"%s\", buf=0x%08x, size=%zu, offset=%lld, fi=0x%08x)\n",
        path, buf, size, offset, fi);

    keysetup(&ctx, BB_DATA->key);

    //  verschlüsselte Dateigröße
    encrypted_file_size = lseek(fi->fh, 0, SEEK_END);
    if (encrypted_file_size == -1) {
        log_msg("Fehler beim Ermitteln der verschlüsselten Dateigröße\n");
        return -EIO;
    }

    //Anzahl der Blöcke
    int num_blocks = encrypted_file_size / (NONCE_LEN + BUFFER_SIZE + TAGLEN);

    // Berechnung der maximalen entschlüsselten Dateigröße (ohne Berücksichtigung des Paddings)
    decrypted_file_size = num_blocks * BUFFER_SIZE;

    log_msg("Anzahl der Blöcke: %d, Maximale entschlüsselte Dateigröße: %lld\n", num_blocks, (long long)decrypted_file_size);

    // Überprüfen, ob der Offset innerhalb der Datei liegt
    if (offset >= decrypted_file_size) {
        return 0;
    }

    // Anpassung der Größe, falls sie über das Dateiende hinausgeht
   // if (offset + size > decrypted_file_size) {
    //    size = decrypted_file_size - offset;
   // }
    if (offset + size > (unsigned long)decrypted_file_size) {
        size = (unsigned long)decrypted_file_size - offset;
    }


    // Berechnung der Start- und Endblöcke
    start_block = offset / BUFFER_SIZE;
    end_block = (offset + size - 1) / BUFFER_SIZE;

    // Offset im ersten Blocks
    offset_in_first_block = offset % BUFFER_SIZE;

    // Berechnung von current_pos (verschlüsselter Dateioffset)
    current_pos = start_block * (NONCE_LEN + BUFFER_SIZE + TAGLEN);

    log_msg("Start Block: %d, End Block: %d\n", start_block, end_block);
    log_msg("Current Position (encrypted file offset): %lld\n", (long long)current_pos);

    // Setze den Dateizeiger auf current_pos
    if (lseek(fi->fh, current_pos, SEEK_SET) == -1) {
        log_msg("Fehler beim Setzen des Dateizeigers\n");
        return -EIO;
    }

    // Variable zur Anpassung der entschlüsselten Dateigröße nach Entfernung des Paddings
    int last_block_adjusted = 0;

    // Schleife über die Blöcke
    for (block = start_block; block <= end_block && total_bytes_read < size; block++) {
        // Lese die Nonce
        if (read(fi->fh, nonce, NONCE_LEN) != NONCE_LEN) {
            log_msg("Fehler beim Lesen der Nonce\n");
            return -EIO;
        }

        // Verarbeite die Nonce als Header
        process_header(&ctx, nonce, NONCE_LEN);

        // Lese den verschlüsselten Block (Ciphertext)
        ssize_t bytes_read = read(fi->fh, buffer, BUFFER_SIZE);
        if (bytes_read != BUFFER_SIZE) {
            log_msg("Fehler beim Lesen des Ciphertexts\n");
            return -EIO;
        }

        // Lese den Tag
        if (read(fi->fh, tag, TAGLEN) != TAGLEN) {
            log_msg("Fehler beim Lesen des Tags\n");
            return -EIO;
        }

        // Block entschlüsseln und Tag überprüfen
        if (decrypt_final(&ctx, buffer, bytes_read, tag, decrypted_buffer) != 0) {
            log_msg("Tag-Überprüfung fehlgeschlagen\n");
            return -EIO;
        }

        // Wenn es der letzte Block der verschlüsselten Datei ist, prüfen auf Padding
        if (block == num_blocks - 1 && !last_block_adjusted) {
            log_msg("Letzter Block der Datei erreicht, prüfe auf Padding...\n");

            int padding_found = 0;
            ssize_t padding_position = -1;

            // Suche nach der Padding
            for (ssize_t j = bytes_read - 7; j >= 0; j--) {
                if (decrypted_buffer[j] == 0x80 &&
                    decrypted_buffer[j + 1] == 0x00 &&
                    decrypted_buffer[j + 2] == 0x00 &&
                    decrypted_buffer[j + 3] == 0x00 &&
                    decrypted_buffer[j + 4] == 0x00 &&
                    decrypted_buffer[j + 5] == 0x00 &&
                    decrypted_buffer[j + 6] == 0x00) {

                    log_msg("Padding gefunden an Position %zd, entferne Padding...\n", j);
                    padding_position = j;
                    padding_found = 1;
                    break;
                }
            }

            // Wenn Padding gefunden wurde, passe bytes_read und decrypted_file_size an
            if (padding_found) {
                bytes_read = padding_position;
                decrypted_file_size -= (BUFFER_SIZE - bytes_read);
                log_msg("Angepasste entschlüsselte Dateigröße: %lld\n", (long long)decrypted_file_size);
            }

            last_block_adjusted = 1; // Dateigröße nur einmal anpassen
        }

        // Berechne die Anzahl der zu kopierenden Bytes
        size_t data_offset = 0;
        size_t data_length = bytes_read;

        // Anpassung für den ersten Block
        if (block == start_block) {
            data_offset = offset_in_first_block;
            if (data_offset >= (size_t)bytes_read) {
                // Keine Daten in diesem Block zu kopieren
                data_length = 0;
            } else {
                data_length -= data_offset;
            }
        }

        // Anpassung für den letzten Lesevorgang
        if (total_bytes_read + data_length > size) {
            data_length = size - total_bytes_read;
        }

        if (data_length > 0) {
            // Kopiere die entschlüsselten Daten in den Puffer
            memcpy(buf + total_bytes_read, decrypted_buffer + data_offset, data_length);
            total_bytes_read += data_length;
        }

        // Aktualisiere current_pos für den nächsten Block
        current_pos += NONCE_LEN + BUFFER_SIZE + TAGLEN;

        // Setze den Dateizeiger für den nächsten Block, falls es weitere Blöcke gibt
        if (block < end_block) {
            if (lseek(fi->fh, current_pos, SEEK_SET) == -1) {
                log_msg("Fehler beim Setzen des Dateizeigers für den nächsten Block\n");
                return -EIO;
            }
        }
    }

    // Gebe die Anzahl der gelesenen Bytes zurück
    return total_bytes_read;
}
//MASTER
// ---------------------------------------------------------------------
int bb_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    poet_ctx_t ctx;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted_buffer[BUFFER_SIZE];
    unsigned char tag[TAGLEN];
    unsigned char nonce[NONCE_LEN];
    off_t encrypted_offset;
    int block_number;

    log_msg("\nbb_write(path=\"%s\", buf=0x%08x, size=%zu, offset=%lld, fi=0x%08x)\n",
        path, buf, size, offset, fi);

    // Schlüssel einrichten
    keysetup(&ctx, BB_DATA->key);

    // Berechnung der Blocknummer und des Offsets innerhalb des Blocks
    block_number = offset / BUFFER_SIZE;
    size_t offset_in_block = offset % BUFFER_SIZE;

    // Berechnung des verschlüsselten Offsets
    encrypted_offset = block_number * (NONCE_LEN + BUFFER_SIZE + TAGLEN);

    log_msg("Blocknummer: %d, Encrypted Offset: %lld\n", block_number, (long long)encrypted_offset);

    // Bereite den Puffer für die Verschlüsselung vor
    memset(buffer, 0, BUFFER_SIZE);

    // Wenn der Offset innerhalb des Blocks nicht null ist oder die Größe kleiner als BUFFER_SIZE ist,
    // müssen der bestehende Block gelesen und aktualisieren werden
    if (offset_in_block != 0 || size < BUFFER_SIZE) {
        // ES müssen den vorhandenen Block lesen
        unsigned char existing_nonce[NONCE_LEN];
        unsigned char existing_tag[TAGLEN];
        unsigned char existing_encrypted_buffer[BUFFER_SIZE];
        unsigned char existing_decrypted_buffer[BUFFER_SIZE];

        // Setze den Dateizeiger auf den verschlüsselten Offset
        if (lseek(fi->fh, encrypted_offset, SEEK_SET) == -1) {
            log_msg("Fehler beim Setzen des Dateizeigers\n");
            return -EIO;
        }

        // Lese die Nonce
        if (read(fi->fh, existing_nonce, NONCE_LEN) == NONCE_LEN) {
            // Verarbeite die Nonce als Header
            process_header(&ctx, existing_nonce, NONCE_LEN);

            // Lese den verschlüsselten Block
            ssize_t bytes_read = read(fi->fh, existing_encrypted_buffer, BUFFER_SIZE);
            if (bytes_read != BUFFER_SIZE) {
                log_msg("Fehler beim Lesen des Ciphertexts\n");
                return -EIO;
            }

            // Lese den Tag
            if (read(fi->fh, existing_tag, TAGLEN) != TAGLEN) {
                log_msg("Fehler beim Lesen des Tags\n");
                return -EIO;
            }

            // Entschlüssele den Block
            if (decrypt_final(&ctx, existing_encrypted_buffer, bytes_read, existing_tag, existing_decrypted_buffer) != 0) {
                log_msg("Fehler beim Entschlüsseln des bestehenden Blocks\n");
                return -EIO;
            }

            // Kopiere die vorhandenen Daten in den Puffer
            memcpy(buffer, existing_decrypted_buffer, BUFFER_SIZE);

            // Verschlüsselungskontext zurücksetzen für den neuen Block
            keysetup(&ctx, BB_DATA->key);
        } else {
            // Wenn kein bestehender Block vorhanden ist, setzen wir den Kontext zurück
            keysetup(&ctx, BB_DATA->key);
        }
    } else {
        // Verschlüsselungskontext zurücksetzen für den neuen Block
        keysetup(&ctx, BB_DATA->key);
    }

    // Kopiere die neuen Daten in den Puffer
    memcpy(buffer + offset_in_block, buf, size);

    // Wenn die Gesamtgröße des Puffers kleiner als BUFFER_SIZE ist, füge Padding hinzu
    if (offset_in_block + size < BUFFER_SIZE) {
        buffer[offset_in_block + size] = 0x80; // ISO/IEC 7816-4 Padding
        memset(buffer + offset_in_block + size + 1, 0, BUFFER_SIZE - (offset_in_block + size + 1));
    }

    // Generiere eine neue Nonce
    if (getrandom(nonce, NONCE_LEN, 0) != NONCE_LEN) {
        log_msg("Fehler bei der Nonce-Generierung\n");
        return -EIO;
    }

    // Verarbeite die Nonce als Header
    process_header(&ctx, nonce, NONCE_LEN);

    // Verschlüssele den Block und generiere den Tag
    encrypt_final(&ctx, buffer, BUFFER_SIZE, encrypted_buffer, tag);

    // Setze den Dateizeiger erneut auf den verschlüsselten Offset
    if (lseek(fi->fh, encrypted_offset, SEEK_SET) == -1) {
        log_msg("Fehler beim Setzen des Dateizeigers vor dem Schreiben\n");
        return -EIO;
    }

    // Schreibe die Nonce
    if (write(fi->fh, nonce, NONCE_LEN) != NONCE_LEN) {
        log_msg("Fehler beim Schreiben der Nonce\n");
        return -EIO;
    }

    // Schreibe den verschlüsselten Block
    if (write(fi->fh, encrypted_buffer, BUFFER_SIZE) != BUFFER_SIZE) {
        log_msg("Fehler beim Schreiben des verschlüsselten Blocks\n");
        return -EIO;
    }

    // Schreibe den Tag
    if (write(fi->fh, tag, TAGLEN) != TAGLEN) {
        log_msg("Fehler beim Schreiben des Tags\n");
        return -EIO;
    }

    // Gebe die Anzahl der geschriebenen Bytes zurück
    return size;
}
//MASTER
int bb_statfs(const char *path, struct statvfs *statv)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_statfs(path=\"%s\", statv=0x%08x)\n",
	    path, statv);
    bb_fullpath(fpath, path);

    // get stats for underlying filesystem
    retstat = log_syscall("statvfs", statvfs(fpath, statv), 0);

    log_statvfs(statv);

    return retstat;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
// this is a no-op in BBFS.  It just logs the call and returns success
int bb_flush(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nbb_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);

    // Setze den Blockzähler zurück, da das Schreiben abgeschlossen ist
   // BB_DATA->block_counter = 0;

    return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int bb_release(const char *path, struct fuse_file_info *fi)
{
    log_msg("\nbb_release(path=\"%s\", fi=0x%08x)\n",
	  path, fi);
    log_fi(fi);

    // We need to close the file.  Had we allocated any resources
    // (buffers etc) we'd need to free them here as well.
    return log_syscall("close", close(fi->fh), 0);
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int bb_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    log_msg("\nbb_fsync(path=\"%s\", datasync=%d, fi=0x%08x)\n",
	    path, datasync, fi);
    log_fi(fi);

    // some unix-like systems (notably freebsd) don't have a datasync call
#ifdef HAVE_FDATASYNC
    if (datasync)
	return log_syscall("fdatasync", fdatasync(fi->fh), 0);
    else
#endif
	return log_syscall("fsync", fsync(fi->fh), 0);
}

#ifdef HAVE_SYS_XATTR_H
/** Note that my implementations of the various xattr functions use
    the 'l-' versions of the functions (eg bb_setxattr() calls
    lsetxattr() not setxattr(), etc).  This is because it appears any
    symbolic links are resolved before the actual call takes place, so
    I only need to use the system-provided calls that don't follow
    them */

/** Set extended attributes */
int bb_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_setxattr(path=\"%s\", name=\"%s\", value=\"%s\", size=%d, flags=0x%08x)\n",
	    path, name, value, size, flags);
    bb_fullpath(fpath, path);

    return log_syscall("lsetxattr", lsetxattr(fpath, name, value, size, flags), 0);
}

/** Get extended attributes */
int bb_getxattr(const char *path, const char *name, char *value, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_getxattr(path = \"%s\", name = \"%s\", value = 0x%08x, size = %d)\n",
	    path, name, value, size);
    bb_fullpath(fpath, path);

    retstat = log_syscall("lgetxattr", lgetxattr(fpath, name, value, size), 0);
    if (retstat >= 0)
	log_msg("    value = \"%s\"\n", value);

    return retstat;
}

/** List extended attributes */
int bb_listxattr(const char *path, char *list, size_t size)
{
    int retstat = 0;
    char fpath[PATH_MAX];
    char *ptr;

    log_msg("\nbb_listxattr(path=\"%s\", list=0x%08x, size=%d)\n",
	    path, list, size
	    );
    bb_fullpath(fpath, path);

    retstat = log_syscall("llistxattr", llistxattr(fpath, list, size), 0);
    if (retstat >= 0) {
	log_msg("    returned attributes (length %d):\n", retstat);
	if (list != NULL)
	    for (ptr = list; ptr < list + retstat; ptr += strlen(ptr)+1)
		log_msg("    \"%s\"\n", ptr);
	else
	    log_msg("    (null)\n");
    }

    return retstat;
}

/** Remove extended attributes */
int bb_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];

    log_msg("\nbb_removexattr(path=\"%s\", name=\"%s\")\n",
	    path, name);
    bb_fullpath(fpath, path);

    return log_syscall("lremovexattr", lremovexattr(fpath, name), 0);
}
#endif

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int bb_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_opendir(path=\"%s\", fi=0x%08x)\n",
	  path, fi);
    bb_fullpath(fpath, path);

    // since opendir returns a pointer, takes some custom handling of
    // return status.
    dp = opendir(fpath);
    log_msg("    opendir returned 0x%p\n", dp);
    if (dp == NULL)
	retstat = log_error("bb_opendir opendir");

    fi->fh = (intptr_t) dp;

    log_fi(fi);

    return retstat;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */

int bb_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi)
{
    int retstat = 0;
    DIR *dp;
    struct dirent *de;

    log_msg("\nbb_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
	    path, buf, filler, offset, fi);
    // once again, no need for fullpath -- but note that I need to cast fi->fh
    dp = (DIR *) (uintptr_t) fi->fh;

    // Every directory contains at least two entries: . and ..  If my
    // first call to the system readdir() returns NULL I've got an
    // error; near as I can tell, that's the only condition under
    // which I can get an error from readdir()
    de = readdir(dp);
    log_msg("    readdir returned 0x%p\n", de);
    if (de == 0) {
	retstat = log_error("bb_readdir readdir");
	return retstat;
    }

    // This will copy the entire directory into the buffer.  The loop exits
    // when either the system readdir() returns NULL, or filler()
    // returns something non-zero.  The first case just means I've
    // read the whole directory; the second means the buffer is full.
    do {
	log_msg("calling filler with name %s\n", de->d_name);
	if (filler(buf, de->d_name, NULL, 0) != 0) {
	    log_msg("    ERROR bb_readdir filler:  buffer full");
	    return -ENOMEM;
	}
    } while ((de = readdir(dp)) != NULL);

    log_fi(fi);

    return retstat;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int bb_releasedir(const char *path, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_msg("\nbb_releasedir(path=\"%s\", fi=0x%08x)\n",
	    path, fi);
    log_fi(fi);

    closedir((DIR *) (uintptr_t) fi->fh);

    return retstat;
}

/** Synchronize directory contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data
 *
 * Introduced in version 2.3
 */
// when exactly is this called?  when a user calls fsync and it
// happens to be a directory? ??? >>> I need to implement this...
int bb_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_msg("\nbb_fsyncdir(path=\"%s\", datasync=%d, fi=0x%08x)\n",
	    path, datasync, fi);
    log_fi(fi);

    return retstat;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *bb_init(struct fuse_conn_info *conn)
{
    log_msg("\nbb_init()\n");

    log_conn(conn);
    log_fuse_context(fuse_get_context());

    return BB_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void bb_destroy(void *userdata)
{
    log_msg("\nbb_destroy(userdata=0x%08x)\n", userdata);
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int bb_access(const char *path, int mask)
{
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nbb_access(path=\"%s\", mask=0%o)\n",
	    path, mask);
    bb_fullpath(fpath, path);

    retstat = access(fpath, mask);

    if (retstat < 0)
	retstat = log_error("bb_access access");

    return retstat;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
// Not implemented.  I had a version that used creat() to create and
// open the file, which it turned out opened the file write-only.

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
int bb_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_msg("\nbb_ftruncate(path=\"%s\", offset=%lld, fi=0x%08x)\n",
	    path, offset, fi);
    log_fi(fi);

    retstat = ftruncate(fi->fh, offset);
    if (retstat < 0)
	retstat = log_error("bb_ftruncate ftruncate");

    return retstat;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
int bb_fgetattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
    int retstat = 0;

    log_msg("\nbb_fgetattr(path=\"%s\", statbuf=0x%08x, fi=0x%08x)\n",
	    path, statbuf, fi);
    log_fi(fi);

    // On FreeBSD, trying to do anything with the mountpoint ends up
    // opening it, and then using the FD for an fgetattr.  So in the
    // special case of a path of "/", I need to do a getattr on the
    // underlying root directory instead of doing the fgetattr().
    if (!strcmp(path, "/"))
	return bb_getattr(path, statbuf);

    retstat = fstat(fi->fh, statbuf);
    if (retstat < 0)
	retstat = log_error("bb_fgetattr fstat");

    log_stat(statbuf);

    return retstat;
}

struct fuse_operations bb_oper = {
  .getattr = bb_getattr,
  .readlink = bb_readlink,
  // no .getdir -- that's deprecated
  .getdir = NULL,
  .mknod = bb_mknod,
  .mkdir = bb_mkdir,
  .unlink = bb_unlink,
  .rmdir = bb_rmdir,
  .symlink = bb_symlink,
  .rename = bb_rename,
  .link = bb_link,
  .chmod = bb_chmod,
  .chown = bb_chown,
  .truncate = bb_truncate,
  .utime = bb_utime,
  .open = bb_open,
  .read = bb_read,
  .write = bb_write,
  /** Just a placeholder, don't set */ // huh???
  .statfs = bb_statfs,
  .flush = bb_flush,
  .release = bb_release,
  .fsync = bb_fsync,

#ifdef HAVE_SYS_XATTR_H
  .setxattr = bb_setxattr,
  .getxattr = bb_getxattr,
  .listxattr = bb_listxattr,
  .removexattr = bb_removexattr,
#endif

  .opendir = bb_opendir,
  .readdir = bb_readdir,
  .releasedir = bb_releasedir,
  .fsyncdir = bb_fsyncdir,
  .init = bb_init,
  .destroy = bb_destroy,
  .access = bb_access,
  .ftruncate = bb_ftruncate,
  .fgetattr = bb_fgetattr
};

void bb_usage()
{
    fprintf(stderr, "usage:  bbfs [FUSE and mount options] rootDir mountPoint\n");
    exit(1);
}
//MASTER
// Hilfsfunktion zum Konvertieren eines einzelnen Hex-Zeichens zu einem Byte-Wert
unsigned char hex_char_to_byte(char hex_char) {
    if (hex_char >= '0' && hex_char <= '9') {
        return hex_char - '0';
    } else if (hex_char >= 'a' && hex_char <= 'f') {
        return hex_char - 'a' + 10;
    } else if (hex_char >= 'A' && hex_char <= 'F') {
        return hex_char - 'A' + 10;
    } else {
        return 0;
    }
}


// Funktion zum Konvertieren eines Hex-Strings in ein Byte-Array
void hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t byte_array_len) {
    for (size_t i = 0; i < byte_array_len; i++) {
        // Konvertiere zwei Hex-Zeichen in ein Byte
        byte_array[i] = (hex_char_to_byte(hex_string[2 * i]) << 4) | hex_char_to_byte(hex_string[2 * i + 1]);
    }
}
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;  // Ungültiges Zeichen
}

void hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++) {
        int high_nibble = hex_char_to_int(hex[2 * i]);
        int low_nibble = hex_char_to_int(hex[2 * i + 1]);
        if (high_nibble == -1 || low_nibble == -1) {
            fprintf(stderr, "Ungültige Hex-Zeichenkette\n");
            exit(1);
        }
        bin[i] = (high_nibble << 4) | low_nibble;
    }
}
int is_directory_empty(const char *path) {
    int is_empty = 1;
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        perror("opendir");
        return -1; // Fehler beim Öffnen des Verzeichnisses
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            is_empty = 0; // Das Verzeichnis ist nicht leer
            break;
        }
    }
    closedir(dir);
    return is_empty;
}

int is_valid_string(const char *str) {
    while (*str) {
        if (!isalpha(*str)) return 0; // Nur alphabetische Zeichen erlauben
        str++;
    }
    return 1;
}

size_t safe_strlen(const char *str, size_t max_len) {
    size_t len = 0;
    while (len < max_len && str[len] != '\0') {
        len++;
    }
    return len;
}

// Funktion zur Überprüfung von Hex-Zeichen
int is_hex_string(const char *str) {
    for (int i = 0; i < KEY_LEN_HEX; i++) {
        if (!isxdigit(str[i])) return 0;
    }
    return 1;
}

void cleanup_and_exit(struct bb_state *bb_data) {
    if (bb_data != NULL) {
        if (bb_data->rootdir != NULL) {
            free(bb_data->rootdir);
        }
        if (bb_data->key != NULL) {
            // Speicher für Schreibzugriff freigeben
            sodium_mprotect_readwrite(bb_data->key);
            // Schlüssel sicher löschen
            sodium_memzero(bb_data->key, CRYPTO_KEYBYTES);
            // Speicher freigeben
            sodium_free(bb_data->key);
        }
        if (bb_data->logfile != NULL) {
            fclose(bb_data->logfile);
        }
        free(bb_data);
    }
}

//MASTER
int main(int argc, char *argv[]) {

    int fuse_stat;
    struct bb_state *bb_data = NULL; // Initialisiere bb_data mit NULL

  // Überprüfen der Argumentanzahl
    if (argc < 3) {
        fputs("Fehler: Ungültige Anzahl von Argumenten.\n", stderr);
        bb_usage();
        return 1;
    }

    // Überprüfen der Argumentlängen mit safe_strlen
    size_t rootdir_len = safe_strlen(argv[argc - 2], MAX_ARG_LENGTH + 1);
    size_t mountpoint_len = safe_strlen(argv[argc - 1], MAX_ARG_LENGTH + 1);

   if (rootdir_len > MAX_ARG_LENGTH || mountpoint_len > MAX_ARG_LENGTH) {
        fputs("Fehler: Argumentlänge zu groß.\n", stderr);
        bb_usage();
        return 1;
    }

    // Kopieren der Argumente in lokale Puffer
    char rootdir[MAX_ARG_LENGTH + 1];
    char mountpoint[MAX_ARG_LENGTH + 1];

    strncpy(rootdir, argv[argc - 2], MAX_ARG_LENGTH);
    rootdir[MAX_ARG_LENGTH] = '\0'; // Nullterminator sicherstellen

    strncpy(mountpoint, argv[argc - 1], MAX_ARG_LENGTH);
    mountpoint[MAX_ARG_LENGTH] = '\0'; // Nullterminator sicherstellen

    if (is_directory_empty(mountpoint) == 0) {
    fputs("Mountpunkt ist nicht leer: ", stderr);

    // Ersetze strnlen durch safe_strlen
    size_t len = safe_strlen(mountpoint, MAX_ARG_LENGTH);

    // Ausgabe des Mountpoints
    fwrite(mountpoint, sizeof(char), len, stderr);
    fputc('\n', stderr);

    return 1;
}


    // Speicher für bb_data mit Nullen initialisieren
    bb_data = calloc(1, sizeof(struct bb_state));
    if (bb_data == NULL) {
        perror("main calloc");
        abort();
    }

  // Libsodium initialisieren
    if (sodium_init() < 0) {
    	fputs("Libsodium konnte nicht initialisiert werden.\n", stderr);
    	cleanup_and_exit(bb_data);
    	return 1;
        }

   // Verhindere das Starten als Root
    if ((getuid() == 0) || (geteuid() == 0)) {
    	fputs("Running BBFS as root opens unacceptable security holes\n", stderr);
    	cleanup_and_exit(bb_data);
    	return 1;
       }

   // FUSE-Version anzeigen
    {
    char version_message[64];
    snprintf(version_message, sizeof(version_message),
             "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);
    fputs(version_message, stderr);
    }


    // rootDir aus den Argumenten extrahieren und in bb_data speichern
    bb_data->rootdir = realpath(argv[argc - 2], NULL);
    if (bb_data->rootdir == NULL) {
        perror("realpath");
        cleanup_and_exit(bb_data);
        return 1;
    }

    argv[argc - 2] = argv[argc - 1];
    argv[argc - 1] = NULL;
    argc--;

    // Sicheren Speicher für den Schlüssel mit Libsodium allokieren
    bb_data->key = (uint8_t *)sodium_malloc(CRYPTO_KEYBYTES);
    if (bb_data->key == NULL) {
        perror("main malloc key");
        cleanup_and_exit(bb_data);
        return 1;
    }

    // Schlüssel von stdin einlesen und auf 32 Zeichen begrenzen
   char *key_input = (char *)sodium_malloc(KEY_LEN_HEX + 2); // Puffer für 32 Zeichen + '\n' + Nullterminator
   if (key_input == NULL) {
    	fputs("Fehler bei der Allokierung von key_input.\n", stderr);
    	cleanup_and_exit(bb_data);
    	return 1;
     }

   // Sperren des Speichers, um Auslagern zu verhindern
    if (sodium_mlock(key_input, KEY_LEN_HEX + 2) != 0) {
    fputs("Fehler beim Sperren von key_input.\n", stderr);
    sodium_free(key_input);
    cleanup_and_exit(bb_data);
    return 1;
}

	// Hinweis an den Benutzer
     fputs("Bitte geben Sie den 32-stelligen hexadezimalen Schlüssel ein: ", stdout);


   // Lesen die Eingabe zeilenweise
    if (fgets(key_input, KEY_LEN_HEX + 2, stdin) == NULL) {
    	fputs("\nFehler beim Lesen des Schlüssels.\n", stderr);
    	sodium_memzero(key_input, KEY_LEN_HEX + 2);
    	sodium_munlock(key_input, KEY_LEN_HEX + 2);
    	sodium_free(key_input);
    	cleanup_and_exit(bb_data);
    	return 1;
}

    // Entfernen das Newline-Zeichen, falls vorhanden
    size_t key_len = strcspn(key_input, "\n");
    key_input[key_len] = '\0';

	// Überprüfen die Länge des Schlüssels
    if (key_len != KEY_LEN_HEX) {
    char error_message[64];
    snprintf(error_message, sizeof(error_message), "\nFehler: Es müssen genau %d Zeichen eingegeben werden.\n", KEY_LEN_HEX);
    fputs(error_message, stderr);
    sodium_memzero(key_input, KEY_LEN_HEX + 2);
    sodium_munlock(key_input, KEY_LEN_HEX + 2);
    sodium_free(key_input);
    cleanup_and_exit(bb_data);
    return 1;
}

    // Überprüfen, ob der Schlüssel ein gültiger Hex-String ist
    if (!is_hex_string(key_input)) {
    fputs("\nFehler: Der Schlüssel darf nur Hexadezimalzeichen enthalten.\n", stderr);
    sodium_memzero(key_input, KEY_LEN_HEX + 2);
    sodium_munlock(key_input, KEY_LEN_HEX + 2);
    sodium_free(key_input);
    cleanup_and_exit(bb_data);
    return 1;
}


    // Überprüfen, ob noch weitere Daten in stdin sind
    int c;
    int extra_input = 0;
    while ((c = getchar()) != EOF && c != '\n') {
        extra_input = 1;
    }

    // Wenn zusätzliche Eingaben vorhanden sind, Fehlermeldung ausgeben
    if (extra_input) {
    	fputs("\nFehler: Es wurden zu viele Zeichen eingegeben.\n", stderr);
    	sodium_memzero(key_input, KEY_LEN_HEX + 2);
    	sodium_munlock(key_input, KEY_LEN_HEX + 2);
    	sodium_free(key_input);
    	cleanup_and_exit(bb_data);
    	return 1;
       }


    // Schlüssel von Hex in Binär konvertieren und in sicheren Speicher kopieren
    hex_to_bin(key_input, bb_data->key, CRYPTO_KEYBYTES);

    // Schlüssel in key_input sicher löschen
    sodium_memzero(key_input, KEY_LEN_HEX + 2);

// Speicher entsperren
if (sodium_munlock(key_input, KEY_LEN_HEX + 2) != 0) {
    fputs("Fehler beim Entsperren von key_input.\n", stderr);
    sodium_memzero(key_input, KEY_LEN_HEX + 2);
    sodium_free(key_input);
    cleanup_and_exit(bb_data);
    return 1;
}

// Speicherzugriff auf keinen Zugriff setzen
if (sodium_mprotect_noaccess(key_input) != 0) {
    fputs("Fehler beim Setzen von noaccess für key_input.\n", stderr);
    sodium_free(key_input);
    cleanup_and_exit(bb_data);
    return 1;
}

// Speicher freigeben
sodium_free(key_input);

// Schlüssel nur für Lesezugriff
if (sodium_mprotect_readonly(bb_data->key) != 0) {
    fputs("Fehler beim Setzen von readonly für bb_data->key.\n", stderr);
    cleanup_and_exit(bb_data);
    return 1;
}

// Log-Datei öffnen
bb_data->logfile = log_open();
if (bb_data->logfile == NULL) {
    fputs("Fehler beim Öffnen der Log-Datei.\n", stderr);
    cleanup_and_exit(bb_data);
    return 1;
}

// Übergabe an FUSE
fputs("about to call fuse_main\n", stderr);
fuse_stat = fuse_main(argc, argv, &bb_oper, bb_data);

char fuse_return_message[64];
snprintf(fuse_return_message, sizeof(fuse_return_message), "fuse_main returned %d\n", fuse_stat);
fputs(fuse_return_message, stderr);


    // Speicher sicher löschen und freigeben
    cleanup_and_exit(bb_data);

    return fuse_stat;
}










