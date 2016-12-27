#ifndef HASHTABLE_H
#define HASHTABLE_H

#include "tlv.h"

#define HASHSIZE 200

typedef struct nlist{
    struct nlist *next;
    unsigned short key;
    tlvInfo_t *value;
}dict_t;

unsigned hash(unsigned char *s);
dict_t *lookup(unsigned short *s, dict_t *hashtab[HASHSIZE]);  //buscar en el dict
dict_t *addItem(unsigned short key, tlvInfo_t *value, dict_t *hashtab[HASHSIZE]);
void displayTable(dict_t *hashtab[HASHSIZE]);


#endif //HASHTABLE_H
