#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tlv.h"



void tlv_init(tlv_t *tlv){
	memset(&tlv->Tag, 0,sizeof(tlv->Tag));
	memset(&tlv->Len, 0,sizeof(tlv->Len));
	memset(&tlv->Val, 0,sizeof(tlv->Val));
}

void tlvInfo_init(tlvInfo_t *tlv){
	tlv_init(&tlv->tlv);
	memset(&tlv->PC, 0,sizeof(tlv->PC));
	memset(&tlv->Source, 0,sizeof(tlv->Source));
	memset(&tlv->Template, 0,sizeof(tlv->Template));
	tlv->RangeLen=NULL;
	tlv->Description =NULL;
}

tlv_t * tlv_parse(unsigned char *arr, int * index){
	/*function to parse one tag,len,value */
	int j;
	tlv_t * tlv;
	if(NULL == (tlv = malloc(sizeof(tlv_t)))){
		printf("%s\n", "malloc failed \n");
	}

	//printf("\n");
	if(arr[*index]==0x9F || arr[*index]==0x5F || arr[*index]==0xBF)
	{
		tlv->Tag = arr[*index]<<8 | arr[*index+1];
		*index += 1;*index += 1;
	}else
	{
		tlv->Tag = arr[*index];
		*index += 1;
	}
	//printf("Tag:%X\n", tlv->Tag);

	tlv->Len = arr[*index];
	*index += 1;
	//printf("len:%X\n", tlv->Len);

	memcpy(tlv->Val, &arr[*index], tlv->Len);
	//printf("val:");
	//for(j=0;j <tlv->Len;j++ ){
	//	printf("%X", tlv->Val[j]);
	//}
	//printf("\n");
	*index += tlv->Len;

	return tlv;
}

void tlv_subParse(tlvInfo_t * t){
/*
	unsigned char num=0;//num of parsed tlv's
	int i;
	for(i = 0; t[i].tlv.Tag!=0; i++){
		num++; //will be used as index for save the sub tlv structs
	}
	for (i = 0; t[i].tlv.Tag!=0; i++)
	{
		if(t[i].PC || t[i].Template!=0){ //case where t[i].tlv.Val has a sub tlv struct to parse
			 printf("size:%d",num);
			t[num+i] = *tlv_parse(t[i].tlv.Val, num);
		}
	}*/
}
