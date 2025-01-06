/*
Weitre Qullen:
POET: https://github.com/medsec/poet/tree/master
https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/src/bbfs.c
Catena: https://github.com/medsec/catena
*/



// von test catena aus master ordner 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "catena.h"

#define SALT_LEN 16

void print_hex(uint8_t *key, int len)
{
  int i;
  for(i=0; i< len; i++) printf("%02x",key[i]);  puts("");
}



int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        return 1;
    }
  const size_t pwdlen = 1 + strlen(argv[1]);
  const size_t hashlen = 64;

const uint8_t salt[SALT_LEN] = {
    0x53, 0x61, 0x66, 0x65, 0x42, 0x61, 0x79, 0x49, 
    0x73, 0x54, 0x68, 0x65, 0x42, 0x65, 0x73, 0x74
};

  //const char *password = argv[1];
  uint8_t* password = malloc(pwdlen);
  strncpy((char*)password, argv[1], pwdlen );
  const char *data     = "I'm a header";
  const uint8_t lambda = LAMBDA;
#ifdef CATENA_INFO
  const uint8_t min_garlic = GARLIC-1;
#else
  const uint8_t min_garlic = GARLIC;
#endif
  const uint8_t garlic = GARLIC;

 // Debug-Ausgabe für die Parameter
   // printf("Test-Catena: GARLIC = %d, LAMBDA = %d, min_garlic = %d\n", garlic, lambda, min_garlic);

  uint8_t hash1[H_LEN];

#ifdef CATENA_INFO
  uint8_t hash2[H_LEN];
  uint8_t hash3[H_LEN];
  uint8_t hash4[H_LEN];
  uint8_t x[H_LEN];

  uint8_t key1[H_LEN];
  uint8_t key2[H_LEN/4];
  uint8_t key3[3*H_LEN+10];
  memset(hash2,0,H_LEN);
  memset(hash3,0,H_LEN);
  memset(hash4,0,H_LEN);
  memset(x,0,H_LEN);
#endif

  memset(hash1,0,H_LEN);

  Catena(password, strlen((char *)password) ,salt, SALT_LEN,
	 (uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
	 hashlen, hash1);
  print_hex(hash1, hashlen);

#ifdef CATENA_INFO

  puts("");
  puts("Keys");

  Catena_KG((uint8_t *) password, strlen(password) ,salt, SALT_LEN,
	    (uint8_t *) data, strlen(data), lambda, min_garlic, garlic,
	    H_LEN, 1,  key1);
  print_hex(key1, H_LEN);

#endif

  return 0;
}

