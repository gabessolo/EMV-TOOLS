//###############################################################################
//TODO:
//	Change hash table "value" type to atlv_t instead of char[]
//	Make atlv_t database
//	Make tlv_decode logic
//###############################################################################
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tlv.h"
#include "hashtable.h"
#include "emvTagList.h"


int main(){
	/*Se hace un test con la cadena hexadecimal 6F1A840E315041592E5359532E4444463031A5088801025F2D02656E
	cuyo significado es el siguiente:
	6F(File Control Information(FCI) Template)
		1A
		84(Dedicated File(DF) Name)
			0E -len
			315041592E5359532E4444463031 - value(1PAY.SYS.DDF01 en hexa)
		A5(File Control information(FCI) Propietary template)
		08-len
			88(Short File Identifier(SFI))
				01- len
				02 -value
			5F2D(language preference)
				02-len
				656E-value
	*/

	dict_t *dict[HASHSIZE];
	memset(dict, 0, sizeof(dict));
	emvInit(dict);
	displayTable(dict);

	unsigned char test[] = {0x6F,0x1A,0x84,0x0E,0x31,0x50,0x41,0x59,0x2E,0x53,0x59,
							0x53,0x2E,0x44,0x44,0x46,0x30,0x31,0xA5,0x08,0x88,0x01,
							0x02,0x5F,0x2D,0x02,0x65,0x6E,
							0x6F,0x1A,0x84,0x0E,0x31,0x50,0x41,0x59,0x2E,0x53,0x59,
							0x53,0x2E,0x44,0x44,0x46,0x30,0x31,0xA5,0x08,0x88,0x01,
							0x02,0x5F,0x2D,0x02,0x65,0x6E};
	//unsigned char test[] = {0x9F, 0x35, 0x00}; //consulta de tag
	unsigned short size = sizeof(test)/sizeof(test[0]);
	tlvInfo_t *t=malloc(sizeof(tlvInfo_t)*size);
	memset(t,0,size);
	tlvInfo_init(t);
	int tindex =0;
	emvparse(test, size, t, &tindex , 0, dict);
	emvPrint_result(t, tindex);

	return 0;
}
