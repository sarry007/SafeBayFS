/*
Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  There are a couple of symbols that need to be #defined before
  #including all the headers.
*/

#ifndef _PARAMS_H_
#define _PARAMS_H_

// The FUSE API has been changed a number of times.  So, our code
// needs to define the version of the API that we assume.  As of this
// writing, the most current API version is 26
#define FUSE_USE_VERSION 26

// need this to get pwrite().  I have to use setvbuf() instead of
// setlinebuf() later in consequence.
#define _XOPEN_SOURCE 500

// maintain bbfs state in here
#include <limits.h>

//#define CRYPTO_KEYBYTES 17  // Schlüsselgröße auf 16 Bytes begrenzen


#include <stdio.h>
struct bb_state {
    FILE *logfile;
    char *rootdir;
    unsigned char *key;  // Dynamischer Speicher für den 16-Byte-Schlüssel
    int block_counter;   // Blockzähler pro Datei
    int ctx_initialized; // Kontext initialisiert pro Datei
};
#define BB_DATA ((struct bb_state *) fuse_get_context()->private_data)

#endif
