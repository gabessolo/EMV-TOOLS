#ifndef TLV_H
#define TLV_H

#define SIZE 200

typedef struct{
	unsigned short Tag;
	unsigned short Len;
	unsigned char Val[SIZE];
}tlv_t;

typedef struct{
	tlv_t tlv;
	unsigned char PC; /*  constructed || primitive */
	unsigned char Source; /* ICC || Terminal */
	unsigned short Template;/* templeate al que pertenece en hexa*/
	unsigned char *RangeLen; /* rango teorico de la longitud del campo */
	unsigned char *Description;
}tlvInfo_t;

void tlv_init(tlv_t *tlv);
void tlvInfo_init(tlvInfo_t * tlv);
tlv_t * tlv_parse(unsigned char arr[], int * index);

#endif
