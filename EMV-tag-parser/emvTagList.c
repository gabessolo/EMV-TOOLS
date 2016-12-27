#include "emvTagList.h"
#include "hashtable.h"
#include <stdlib.h>
#include <stdio.h>

#define CONSTRUCTED 1
#define PRIMITIVE 0
#define ISSUER 2
#define ICC 1
#define TERMINAL 0

tlvInfo_t * emvInfo_set(unsigned char PC,unsigned char Source,
	unsigned short Template, unsigned char *RangeLen, unsigned char *Description){

	tlvInfo_t *t= malloc(sizeof(tlvInfo_t));
	tlvInfo_init(t);
	t->PC = PC;
	t->Source = Source;
	t->Template=Template;
	t->RangeLen = RangeLen;
	t->Description = Description;
	return t;
}

int emvInfo_get(tlvInfo_t *t,int * tindex, dict_t *hashtab[HASHSIZE]){

	dict_t * dict;

	dict = lookup(&t[*tindex].tlv.Tag, hashtab);
	if(dict == NULL){
		//printf("%s\n","Tag not in list" );
		return 1;
	}
	t[*tindex].PC = dict->value->PC;
	t[*tindex].Source = dict->value->Source;
	t[*tindex].Template = dict->value->Template;
	t[*tindex].RangeLen = dict->value->RangeLen;
	t[*tindex].Description = dict->value->Description;
	return 0;
}

tlvInfo_t emvparse(unsigned char arr[], unsigned short size, tlvInfo_t * t, int * tindex, int index, dict_t *hashtab[HASHSIZE]){
	/* 	arr: Value
		size: numero de elementos de arr
		t: array de tlvInfo_t para ir guardando los resultados
		tindex:index en el que guardar cada tlv dentro de t
		index: index para saber la reading position de los campos Value de tlv
		hashtab: diccionario para consultar los datos de los tags previamente almacenados
		*/
		t[*tindex].tlv =  *tlv_parse(arr, &index);
		if(1==emvInfo_get(t, tindex, hashtab)){
			//Tag desconocido, no lo guardamos ximplemente por no actualizar *tindex
			printf("Tag desconocido: %X\n", t[*tindex].tlv.Tag);
		}
		*tindex +=1;

		if(t[*tindex-1].PC == CONSTRUCTED){
		 	emvparse(t[*tindex-1].tlv.Val, \
				t[*tindex-1].tlv.Len, t, tindex, 0 , hashtab);
		}
		if(index >= size){
			return;
		}
		{ //several consecutive primite tlv's
			return emvparse(&arr[index], size-index , t, tindex, 0 , hashtab);
		}
}

void emvPrint_result(tlvInfo_t* t, int tindex){
	int i,j;
	int tabs=1;
	int composedLen=0;
	int trackLen =0;
	printf("\n" );
	for(i=0; i<tindex; i++){
		if(trackLen >=composedLen) tabs--;
		printf("%sTag:%X(%s)\n", emvPrint_tabs(tabs), t[i].tlv.Tag, t[i].Description);
		printf("%slen:%X(decimal: %d )\n", emvPrint_tabs(tabs+1), t[i].tlv.Len, t[i].tlv.Len);
		printf("%sTemplate:%X\n", emvPrint_tabs(tabs+1), t[i].Template);
		printf("%sSource:%s\n", emvPrint_tabs(tabs+1), emvPrint_Source(t[i].Source));
		printf("%sType:%s\n", emvPrint_tabs(tabs+1), t[i].PC?"Constructed" : "Primitive");
		printf("%sRangeLen:%s\n", emvPrint_tabs(tabs+1), t[i].RangeLen);
		if(t[i].PC == CONSTRUCTED){
			trackLen =0;
			composedLen = 0;
			composedLen = t[i].tlv.Len;
			tabs++;
		}else{
			printf("%s%s",emvPrint_tabs(tabs+1), "val:");
			for(j=0; j< t[i].tlv.Len; j++){
				printf("%X", t[i].tlv.Val[j]);
			}
			printf("\n");
			trackLen += sizeof(t[i].tlv.Tag);
			trackLen += sizeof(t[i].tlv.Len);
			trackLen += t[i].tlv.Len;
		}
	}
}

char * emvPrint_tabs(int numTabs){
	switch (numTabs) {
		case 0: return ""; break;
		case 1: return "\t"; break;
		case 2: return "\t\t"; break;
		case 3: return "\t\t\t"; break;
		case 4: return "\t\t\t\t"; break;
		case 5: return "\t\t\t\t\t"; break;
		case 6: return "\t\t\t\t\t\t"; break;
		case 7: return "\t\t\t\t\t\t\t"; break;
		case 8: return "\t\t\t\t\t\t\t\t"; break;
		case 9: return "\t\t\t\t\t\t\t\t\t"; break;
		default: return "\t\t\t\t\t\t\t\t\t"; break;
	}
}

char * emvPrint_Source(unsigned char source){
	switch (source) {
		case ICC:  return "ICC"; break;
		case TERMINAL: return "Terminal"; break;
		case ISSUER:  return "Issuer"; break;
	}
}

void emvInit(dict_t *hashtab[HASHSIZE])
{
	addItem(0x9F01,emvInfo_set(PRIMITIVE,TERMINAL,0,"6","Acquirer Identifier"), hashtab);
	addItem(0x9F40,emvInfo_set(PRIMITIVE,TERMINAL,0,"5","Additional Terminal Capabilities"), hashtab);
	addItem(0x81,emvInfo_set(PRIMITIVE,TERMINAL,0,"4","Amount, Authorised (Binary)"), hashtab);
	addItem(0x9F02,emvInfo_set(PRIMITIVE,TERMINAL,0,"6","Amount, Authorised (Numeric)"), hashtab);
	addItem(0x9F04,emvInfo_set(PRIMITIVE,TERMINAL,0,"4","Amount, Other (Binary)"), hashtab);
	addItem(0x9F03, emvInfo_set(PRIMITIVE,TERMINAL,0,"6","Amount, Other (Numeric)"), hashtab);
	addItem(0x9F3A, emvInfo_set(PRIMITIVE,TERMINAL,0,"4","Amount, Reference Currency"), hashtab);
	addItem(0x9F26, emvInfo_set(PRIMITIVE,ICC,0x7780,"8","Application Cryptogram"), hashtab);
	addItem(0x9F42, emvInfo_set(PRIMITIVE,ICC,0x7077,"2","Application Currency Code"), hashtab);
	addItem(0x9F44, emvInfo_set(PRIMITIVE,ICC,0x7077,"1","Application Currency Exponent"), hashtab);
	addItem(0x9F05, emvInfo_set(PRIMITIVE,ICC,0x7077,"1-32","Application Discretionary Data"), hashtab);
	addItem(0x5F25, emvInfo_set(PRIMITIVE,ICC,0x7077,"3","Application Effective Date"), hashtab);
	addItem(0x5F24, emvInfo_set(PRIMITIVE,ICC,0x7077,"3","Application Expiration Date"), hashtab);
	addItem(0x94, emvInfo_set(PRIMITIVE,ICC,0x7780,"0-252","Application File Locator (AFL)"), hashtab);
	addItem(0x4F, emvInfo_set(PRIMITIVE,ICC,0x61,"5-16","Application Identifier (AID) – card"), hashtab);
	addItem(0x9F06, emvInfo_set(PRIMITIVE,TERMINAL,0,"5-16","Application Identifier (AID) – terminal"), hashtab);
	addItem(0x82, emvInfo_set(PRIMITIVE,ICC,0x7780,"2","Application Interchange Profile"), hashtab);
	addItem(0x50, emvInfo_set(PRIMITIVE,ICC,0x61A5,"1-16","Application Label"), hashtab);
	addItem(0x9F12, emvInfo_set(PRIMITIVE,ICC,0x61A5,"1-16","Application Preferred Name"), hashtab);
	addItem(0x5A, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-10","Application Primary Account Number (PAN)"), hashtab);
	addItem(0x5F34, emvInfo_set(PRIMITIVE,ICC,0x7077,"1","Application Primary Account Number (PAN) Sequence Number"), hashtab);
	addItem(0x87, emvInfo_set(PRIMITIVE,ICC,0x61A5,"1","Application Priority Indicator"), hashtab);
	addItem(0x9F3B, emvInfo_set(PRIMITIVE,ICC,0x7077,"2-8","Application Reference Currency"), hashtab);
	addItem(0x9F43, emvInfo_set(PRIMITIVE,ICC,0x7077,"1-4","Application Reference Currency Exponent"), hashtab);
	addItem(0x61, emvInfo_set(CONSTRUCTED,ICC,0x70,"0-252","Application Template"), hashtab);
	addItem(0x9F36, emvInfo_set(PRIMITIVE,ICC,0x7080,"2","Application Transaction Counter (ATC)"), hashtab);
	addItem(0x9F07, emvInfo_set(PRIMITIVE,ICC,0x7077,"2","Application Usage Control/geographic restrictions"), hashtab);
	addItem(0x9F08, emvInfo_set(PRIMITIVE,ICC,0x7077,"2","Application Version Number"), hashtab);
	addItem(0x9F09, emvInfo_set(PRIMITIVE,TERMINAL,0,"2","Application Version Number"), hashtab);
	addItem(0x89, emvInfo_set(PRIMITIVE,ISSUER,0,"6","Authorisation Code"), hashtab);
	addItem(0x8A, emvInfo_set(PRIMITIVE,ISSUER,0,"2","Authorisation Response Code"), hashtab);
	addItem(0x5F54, emvInfo_set(PRIMITIVE,ICC,0xBF0C73,"8/11","Bank Identifier Code (BIC)"), hashtab);
	addItem(0x8C, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-252","Card Risk Management Data Object List 1 (CDOL1)"), hashtab);
	addItem(0x8D, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-252","Card Risk Management Data Object List 2 (CDOL2)"), hashtab);
	addItem(0x5F20, emvInfo_set(PRIMITIVE,ICC,0x7077,"2-26","Cardholder Name"), hashtab);
	addItem(0x9F0B, emvInfo_set(PRIMITIVE,ICC,0x7077,"27-45","Cardholder Name Extended"), hashtab);
	addItem(0x8E, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-252","Cardholder Verification Method (CVM) List"), hashtab);
	addItem(0x9F34, emvInfo_set(PRIMITIVE,TERMINAL,0,"3","Cardholder Verification Method (CVM) Results"), hashtab);
	addItem(0x8F, emvInfo_set(PRIMITIVE,ICC,0x7077,"1","Certification Authority Public Key Index"), hashtab);
	addItem(0x9F22, emvInfo_set(PRIMITIVE,TERMINAL,0,"1","Certification Authority Public Key Index"), hashtab);
	addItem(0x83, emvInfo_set(PRIMITIVE,TERMINAL,0,"var","Command Template"), hashtab);
	addItem(0x9F27, emvInfo_set(PRIMITIVE,ICC,0x7780,"1","Cryptogram Information Data"), hashtab);
	addItem(0x9F45, emvInfo_set(PRIMITIVE,ICC,0,"2","Data Authentication Code"), hashtab);
	addItem(0x84, emvInfo_set(PRIMITIVE,ICC,0x6F,"5-16","Dedicated File (DF) Name"), hashtab);
	addItem(0x9D, emvInfo_set(PRIMITIVE,ICC,0x61,"5-16","Directory Definition File (DDF) Name"), hashtab);
	addItem(0x73, emvInfo_set(CONSTRUCTED,ICC,0x61,"0-252","Directory Discretionary Template"), hashtab);
	addItem(0x9F49, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-252","Dynamic Data Authentication Data Object List (DDOL)"), hashtab);
	addItem(0x70, emvInfo_set(CONSTRUCTED,ICC,0,"var","EMV Proprietary Template"), hashtab);
	addItem(0xBF0C, emvInfo_set(CONSTRUCTED,ICC,0xA5,"0-222","File Control Information (FCI) Issuer Discretionary Data"), hashtab);
	addItem(0xA5, emvInfo_set(CONSTRUCTED,ICC,0x6F,"var","File Control Information (FCI) Proprietary Template"), hashtab);
	addItem(0x6F, emvInfo_set(CONSTRUCTED,ICC,0,"0-252","File Control Information(FCI) Template"), hashtab);
	addItem(0x9F4C, emvInfo_set(PRIMITIVE,ICC,0,"2-8","ICC Dynamic Number"), hashtab);
	addItem(0x9F2D, emvInfo_set(PRIMITIVE,ICC,0x7077,"NI","Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate"), hashtab);
	addItem(0x9F2E, emvInfo_set(PRIMITIVE,ICC,0x7077,"1/3","Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent"), hashtab);
	addItem(0x9F2F, emvInfo_set(PRIMITIVE,ICC,0x7077,"TODO","Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder"), hashtab);
	addItem(0x9F46, emvInfo_set(PRIMITIVE,ICC,0x7077,"NI","Integrated Circuit Card (ICC) Public Key Certificate"), hashtab);
	addItem(0x9F47, emvInfo_set(PRIMITIVE,ICC,0x7077,"1-3","Integrated Circuit Card (ICC) Public Key Exponent"), hashtab);
	addItem(0x9F48, emvInfo_set(PRIMITIVE,ICC,0x7077,"TODO","Integrated Circuit Card (ICC) Public Key Remainder"), hashtab);
	addItem(0x9F1E, emvInfo_set(PRIMITIVE,TERMINAL,0,"8","Interface Device (IFD) Serial Number"), hashtab);
	addItem(0x5F53, emvInfo_set(PRIMITIVE,ICC,0xBF0C73,"0-34","International Bank Account Number (IBAN)"), hashtab);
	addItem(0x9F0D, emvInfo_set(PRIMITIVE,ICC,0x7077,"5","Issuer Action Code – Default"), hashtab);
	addItem(0x9F0E, emvInfo_set(PRIMITIVE,ICC,0x7077,"5","Issuer Action Code – Denial"), hashtab);
	addItem(0x9F0F, emvInfo_set(PRIMITIVE,ICC,0x7077,"5","Issuer Action Code – Online"), hashtab);
	addItem(0x9F10, emvInfo_set(PRIMITIVE,ICC,0x7780,"0-32","Issuer Application Data"), hashtab);
	addItem(0x91, emvInfo_set(PRIMITIVE,ISSUER,0,"0-32","Issuer Authentication Data"), hashtab);
	addItem(0x9F11, emvInfo_set(PRIMITIVE,ICC,0,"1","Issuer Code Table Index"), hashtab);
	addItem(0x5F28, emvInfo_set(PRIMITIVE,ICC,0x7077,"2","Issuer Country Code"), hashtab);
	addItem(0x5F55, emvInfo_set(PRIMITIVE,ICC,0xBF0C73,"2","Issuer Country Code (alpha2 format)"), hashtab);
	addItem(0x5F56, emvInfo_set(PRIMITIVE,ICC,0xBF0C73,"3","Issuer Country Code (alpha3 format)"), hashtab);
	addItem(0x42, emvInfo_set(PRIMITIVE,ICC,0xBF0C73,"3","Issuer Identification Number (IIN)"), hashtab);
	addItem(0x90, emvInfo_set(PRIMITIVE,ICC,0x7077,"NCA","Issuer Public Key Certificate"), hashtab);
	addItem(0x9F32, emvInfo_set(PRIMITIVE,ICC,0x7077,"1-3","Issuer Public Key Exponent"), hashtab);
	addItem(0x92, emvInfo_set(PRIMITIVE,ICC,0x7077,"TODO","Issuer Public Key Remainder"), hashtab);
	addItem(0x86, emvInfo_set(PRIMITIVE,ISSUER,0x7172,"0-261","Issuer Script Command"), hashtab);
	addItem(0x9F18, emvInfo_set(PRIMITIVE,ISSUER,0x7172,"4","Issuer Script Identifier"), hashtab);
	addItem(0x71, emvInfo_set(CONSTRUCTED,ISSUER,0,"var","Issuer Script Template 1"), hashtab);
	addItem(0x72, emvInfo_set(CONSTRUCTED,ISSUER,0,"var","Issuer Script Template 2"), hashtab);
	addItem(0x5F50, emvInfo_set(PRIMITIVE,ICC,0xBF0C73,"var","Issuer URL"), hashtab);
	addItem(0x5F2D, emvInfo_set(PRIMITIVE,ICC,0xA5,"2-8","Language Preference"), hashtab);
	addItem(0x9F13, emvInfo_set(PRIMITIVE,ICC,0,"2","Last Online Application Transaction Counter (ATC) Register"), hashtab);
	addItem(0x9F4D, emvInfo_set(PRIMITIVE,ICC,0,"2","Log Entry"), hashtab);
	addItem(0x9F4F, emvInfo_set(PRIMITIVE,ICC,0,"var","Log Format"), hashtab);
	addItem(0x9F14, emvInfo_set(PRIMITIVE,ICC,0,"1","Lower Consecutive Offline Limit"), hashtab);
	addItem(0x9F15, emvInfo_set(PRIMITIVE,TERMINAL,0,"2","Merchant Category Code"), hashtab);
	addItem(0x9F16, emvInfo_set(PRIMITIVE,TERMINAL,0,"15","Merchant Identifier"), hashtab);
	addItem(0x9F4E, emvInfo_set(PRIMITIVE,TERMINAL,0,"var","Merchant Name and Location"), hashtab);
	addItem(0x9F17, emvInfo_set(PRIMITIVE,ICC,0,"1","Personal Identification Number (PIN) Try Counter"), hashtab);
	addItem(0x9F39, emvInfo_set(PRIMITIVE,TERMINAL,0,"1","Point-of-Service (POS) Entry Mode"), hashtab);
	addItem(0x9F38, emvInfo_set(PRIMITIVE,ICC,0xA5,"var","Processing Options Data Object List (PDOL)"), hashtab);
	addItem(0x80, emvInfo_set(PRIMITIVE,ICC,0,"var","Response Message Template Format 1"), hashtab);
	addItem(0x77, emvInfo_set(CONSTRUCTED,ICC,0,"var","Response Message Template Format 2"), hashtab);
	addItem(0x5F30, emvInfo_set(PRIMITIVE,ICC,0x7077,"2","Service Code"), hashtab);
	addItem(0x88, emvInfo_set(PRIMITIVE,ICC,0xA5,"1","Short File Identifier (SFI)"), hashtab);
	addItem(0x9F4B, emvInfo_set(PRIMITIVE,ICC,0,"NIC","Signed Dynamic Application Data"), hashtab);
	addItem(0x93, emvInfo_set(PRIMITIVE,ICC,0x7077,"NI","Signed Static Application Data"), hashtab);
	addItem(0x9F4A, emvInfo_set(PRIMITIVE,ICC,0x7077,"var","Static Data Authentication Tag List"), hashtab);
	addItem(0x9F33, emvInfo_set(PRIMITIVE,TERMINAL,0,"3","Terminal Capabilities"), hashtab);
	addItem(0x9F1A, emvInfo_set(PRIMITIVE,TERMINAL,0,"2","Terminal Country Code"), hashtab);
	addItem(0x9F1B, emvInfo_set(PRIMITIVE,TERMINAL,0,"4","Terminal Floor Limit"), hashtab);
	addItem(0x9F1C, emvInfo_set(PRIMITIVE,TERMINAL,0,"8","Terminal Identification"), hashtab);
	addItem(0x9F1D, emvInfo_set(PRIMITIVE,TERMINAL,0,"1-8","Terminal Risk Management Data"), hashtab);
	addItem(0x9F35, emvInfo_set(PRIMITIVE,TERMINAL,0,"1","Terminal Type"), hashtab);
	addItem(0x95, emvInfo_set(PRIMITIVE,TERMINAL,0,"5","Terminal Verification Results"), hashtab);
	addItem(0x9F1F, emvInfo_set(PRIMITIVE,ICC,0x7077,"var","Track 1 Discretionary Data"), hashtab);
	addItem(0x9F20, emvInfo_set(PRIMITIVE,ICC,0x7077,"var","Track 2 Discretionary Data"), hashtab);
	addItem(0x57, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-19","Track 2 Equivalent Data"), hashtab);
	addItem(0x98, emvInfo_set(PRIMITIVE,TERMINAL,0x7077,"20","Transaction Certificate (TC) Hash Value"), hashtab);
	addItem(0x97, emvInfo_set(PRIMITIVE,ICC,0x7077,"0-252","Transaction Certificate Data Object List (TDOL)"), hashtab);
	addItem(0x5F2A, emvInfo_set(PRIMITIVE,TERMINAL,0,"2","Transaction Currency Code"), hashtab);
	addItem(0x5F36, emvInfo_set(PRIMITIVE,TERMINAL,0,"1","Transaction Currency Exponent"), hashtab);
	addItem(0x9A, emvInfo_set(PRIMITIVE,TERMINAL,0,"3","Transaction Date"), hashtab);
	addItem(0x99, emvInfo_set(PRIMITIVE,TERMINAL,0,"var","Transaction Personal Identification Number (PIN) Data"), hashtab);
	addItem(0x9F3C, emvInfo_set(PRIMITIVE,TERMINAL,0,"2","Transaction Reference Currency Code"), hashtab);
	addItem(0x9F3D, emvInfo_set(PRIMITIVE,TERMINAL,0,"1","Transaction Reference Currency Exponent"), hashtab);
	addItem(0x9F41, emvInfo_set(PRIMITIVE,TERMINAL,0,"2-4","Transaction Sequence Counter"), hashtab);
	addItem(0x9B, emvInfo_set(PRIMITIVE,TERMINAL,0,"2","Transaction Status Information"), hashtab);
	addItem(0x9F21, emvInfo_set(PRIMITIVE,TERMINAL,0,"3","Transaction Time"), hashtab);
	addItem(0x9C, emvInfo_set(PRIMITIVE,TERMINAL,0,"1","Transaction Type"), hashtab);
	addItem(0x9F37, emvInfo_set(PRIMITIVE,TERMINAL,0,"4","Unpredictable Number"), hashtab);
	addItem(0x9F23, emvInfo_set(PRIMITIVE,ICC,0x7077,"1","Upper Consecutive Offline Limit"), hashtab);
}
