#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hashtable.h"

unsigned hash(unsigned char *s)
{
    unsigned hashval;
    for (hashval = 0; *s != '\0'; s++)
        hashval = *s + 31 * hashval;
    return hashval % HASHSIZE;
}


dict_t *lookup(unsigned short *s, dict_t *hashtab[HASHSIZE])
{
    dict_t *np;
    unsigned char str[15];
    sprintf(str,"%d",*s);
    for (np = hashtab[hash(str)]; np != NULL; np = np->next)
        if (*s == np->key)
            return np; /* found */
    return NULL; /* not found */
}

dict_t *addItem(unsigned short key, tlvInfo_t *value, dict_t *hashtab[HASHSIZE])
{
    dict_t *np;
    unsigned char str[15];
    sprintf(str,"%d",key);
    unsigned hashval;
    if ((np = lookup(&key, hashtab)) == NULL) { // not found
        np = (dict_t *) malloc(sizeof(*np));
        if (np == NULL)
            return NULL;
        hashval = hash(str);
        np->next = hashtab[hashval];
        hashtab[hashval] = np;
        np->key = key;
        np->value = value;
        if(&np->key==NULL || np->value==NULL) return NULL;
    } else // already there
        free((void *) np->value); //free previous value

    if (np->value == NULL)
        return NULL;
    return np;
}


void displayTable(dict_t *hashtab[HASHSIZE])
{
    int i;
    dict_t *t;
    printf("Tag:\t\tPC:\t\t\tSource:\t\t\tTemplate:\tRange:\t\tDescription:\n");
    for(i=0;i<HASHSIZE;i++)
    {
        if(hashtab[i]==NULL)continue;
        else
    	{
      		t=hashtab[i];
      		for(;t!=NULL;t=t->next)
      		{
                    printf("%X\t\t%s\t\t%s\t\t%X\t\t%s\t\t%s\n",t->key,t->value->PC?"Constructed":"Primitive",
                                                         t->value->Source?"ICC\t":"Terminal",t->value->Template,
                                                        t->value->RangeLen, t->value->Description);
                }
  		}
  	}
}
