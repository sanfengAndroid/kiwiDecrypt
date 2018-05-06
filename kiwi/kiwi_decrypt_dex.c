#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"kiwi_decrypt_dex.h"


unsigned char *ptr_write_position = NULL;
const int MOD_ADLER = 65521;
unsigned char digest[kSHA1DigestLen];
int main()
{
	FILE *dex_file = fopen("classes.dex", "rb");
	fseek(dex_file, 0, 2);
	size_t original_dex_length = ftell(dex_file);
	fseek(dex_file, 0, 0);	
	FILE *data_file = fopen("data.dat", "rb");
	fseek(data_file, 0, 2);
	size_t dexrypt_data_length = ftell(data_file);
	fseek(data_file, 0, 0);	
	
	void *data = malloc(original_dex_length * 2 + dexrypt_data_length);	//申请足够的空间方便后面写数据
	memset(data, 0, original_dex_length* 2 + dexrypt_data_length);
	fread(data, original_dex_length, 1, dex_file);
	//把解密后的数据放在文件最后,由于将整个codeOff偏移改为0,而写入需要uleb128,因此只能将整个classDataOff重构
	fread((void *)((char *)data + original_dex_length), dexrypt_data_length, 1, data_file);
	fclose(dex_file);
	fclose(data_file);	

	/***********读取数据***************/
	DexHeader* pHeader = (DexHeader*)data;
	ptr_write_position = (unsigned char*)pHeader + original_dex_length + dexrypt_data_length;
	void *decrypt_data = (void *)((char *)data + original_dex_length);	//解密后数据的起始偏移

	int encrypt_fuction_num = 10;
	unsigned int method_id_item_array[encrypt_fuction_num];
	unsigned int real_codeOff_array[encrypt_fuction_num];
	size_t modify_dex_length = 0;
	printf("decrypt function maps table:\n");
	for(int i = 0; i < encrypt_fuction_num; i++)
	{
		method_id_item_array[i] = *(unsigned int *)((char *)decrypt_data  + 8 * (i)) ^ 0x59BD07F2;
		//这里计算出来偏移-0x20,是整个code_item结构体
		real_codeOff_array[i] = (*(unsigned int *)((char *)decrypt_data + 8 * (i) + 4) ^ 0x59BD07F2) - 0x20;
		printf("method_id_item_array[%d] = %d real_codeOff_array[%d] = 0x%0X\n", i, method_id_item_array[i], i, real_codeOff_array[i]);
	}
	modify_dex_length = handle_dex(pHeader, original_dex_length, decrypt_data, &method_id_item_array[0], &real_codeOff_array[0], encrypt_fuction_num);
	FILE *save = fopen("classes2.dex", "wb");
	pHeader->fileSize = modify_dex_length;		//修正文件大小
	
	printf("modify new dex file signature:\n");
	int nonum = sizeof(pHeader->magic) + sizeof(pHeader->checksum) + kSHA1DigestLen;
	dexComputeSHA1Digest(data + nonum, pHeader->fileSize - nonum, digest);
	for(int i = 0; i < kSHA1DigestLen; i++)
	{
		pHeader->signature[i] = digest[i];
	}
	pHeader->checksum = adler32(data + sizeof(pHeader->magic) + sizeof(pHeader->checksum), pHeader->fileSize - sizeof(pHeader->magic) - sizeof(pHeader->checksum));
	if (modify_dex_length > 0)
		fwrite(data, modify_dex_length, 1, save);
	fclose(save);
	free(data);		
	return 0;
}

unsigned int handle_dex(DexHeader *pHeader, size_t original_dex_length, char *decrypt_data, unsigned int *method_id_item_array, unsigned int *real_codeOff_array, int encrypt_function_num)
{	
	unsigned int length = pHeader->classDefsSize;
	DexClassDataHeader *pDexClassDataHeader = (DexClassDataHeader *)malloc(sizeof(DexClassDataHeader));
	DexField *pDexField = (DexField *)malloc(sizeof(DexField));
	DexMethod *pDexDirectMethod = NULL;
	DexMethod *pDexVirtualMethod = NULL;
	unsigned char *pStart = NULL, *pStop = NULL;	//用来记录地址,然后用来重写  
	int isCorrect = 0;//控制是否要重构classData
	printf("found classDef size: %d\n", pHeader->classDefsSize);
	for(int i = 0; i < length; i++)
	{
		DexClassDef *pDexClassDef = (DexClassDef *)((char *)pHeader + pHeader->classDefsOff + i * sizeof(DexClassDef));	
		if(0 == pDexClassDef->classDataOff)	//过滤没有classDataOff的
			continue;				
		isCorrect = 0;
		const unsigned char* pDexClassData = (char *)pHeader + pDexClassDef->classDataOff;
		pStart = (unsigned char*)pDexClassData;
		dexReadClassDataHeader(&pDexClassData, pDexClassDataHeader);			
		for(int j = 0; j < (int)pDexClassDataHeader->staticFieldsSize; j++)
		{
			dexReadClassDataField(&pDexClassData, pDexField);
		}				
		for(int j = 0; j < (int)pDexClassDataHeader->instanceFieldsSize; j++)
		{
			dexReadClassDataField(&pDexClassData, pDexField);
		}
		pStop = (unsigned char*)pDexClassData;
				
		/************************************/
		unsigned int method_id = 0;
		unsigned int encrypt_index = 0;
		if (pDexClassDataHeader->directMethodsSize > 0)
		{
			pDexDirectMethod = (DexMethod *)malloc(pDexClassDataHeader->directMethodsSize * sizeof(DexMethod));			
			for (int j = 0; j < (int)pDexClassDataHeader->directMethodsSize; j++)
			{
				dexReadClassDataMethod(&pDexClassData, &pDexDirectMethod[j]);
				method_id += pDexDirectMethod[j].methodIdx;				
				encrypt_index = isEncryptFunction(method_id, method_id_item_array, encrypt_function_num);
				if (encrypt_index != -1)	//找到要修复的方法
				{
					pDexDirectMethod[j].accessFlags &= ~ACC_NATIVE;
					pDexDirectMethod[j].codeOff = (unsigned int)(original_dex_length+ real_codeOff_array[encrypt_index]);
				
					printf("pStart=%08x pStop=%08x\n", pStart, pStop);
					printf("modify decrypt direct  function! i = %d method_id = %08X accessFlags = %08X codeOff = %08X\n", i, pDexDirectMethod[j].methodIdx, pDexDirectMethod[j].accessFlags, pDexDirectMethod[j].codeOff);
					isCorrect = 1;
				}				
			}			
		}
		
		method_id = 0;
		if (pDexClassDataHeader->virtualMethodsSize > 0)
		{
			pDexVirtualMethod = malloc(pDexClassDataHeader->virtualMethodsSize * sizeof(DexMethod));			
			for (int j = 0; j < (int)pDexClassDataHeader->virtualMethodsSize; j++)
			{
				dexReadClassDataMethod(&pDexClassData, &pDexVirtualMethod[j]);			
				method_id += pDexVirtualMethod[j].methodIdx;
				encrypt_index = isEncryptFunction(method_id, method_id_item_array, encrypt_function_num);
				if (encrypt_index != -1)	////找到要修复的方法
				{
					pDexVirtualMethod[j].accessFlags &= ~ACC_NATIVE;
					pDexVirtualMethod[j].codeOff = (unsigned int)(original_dex_length+ real_codeOff_array[encrypt_index]);
					printf("modify decrypt virtual function! i = %d method_id = %08X accessFlags = %08X codeOff = %08X\n", i, pDexVirtualMethod[j].methodIdx, pDexVirtualMethod[j].accessFlags, pDexVirtualMethod[j].codeOff);					
					isCorrect = 1;
				}
				
			}
		}	
		
		if(isCorrect)
		{
			pDexClassDef->classDataOff = (unsigned int)(ptr_write_position - (unsigned char*)pHeader);
			memcpy((void *)ptr_write_position, pStart, pStop -pStart);
			ptr_write_position = ptr_write_position + (unsigned int)(pStop - pStart);
			for(int j = 0; j < (int)pDexClassDataHeader->directMethodsSize; j++)
			{
				ptr_write_position = dexWriteClassDataMethod(ptr_write_position, &pDexDirectMethod[j]);
			}
			for(int j = 0; j < pDexClassDataHeader->virtualMethodsSize; j++)
			{
				ptr_write_position = dexWriteClassDataMethod(ptr_write_position, &pDexVirtualMethod[j]);
			}
		}
		
	}
	free(pDexField);
	int modify_num = (int)(ptr_write_position - (unsigned char *)pHeader) % 8;
	
	while(modify_num)	//这里修正文件长度为8字节的倍数
	{
		*ptr_write_position++ = 0;
		modify_num--;
	}
	return (unsigned int)(ptr_write_position - (unsigned char *)pHeader);
}

int isEncryptFunction(unsigned int method_id_item, unsigned int *method_id_item_array, int num)
{
	for(int i = 0; i < num; i++)
	{
		if (method_id_item == method_id_item_array[i])
		{
			printf("[+] found fun: method_id_item = %d in method_id_item_array index = %d\n", method_id_item, i);
			return i;
		}
			
	}
	return -1;
}

void dexReadClassDataHeader(const unsigned char** pData,DexClassDataHeader *pHeader)
{
	pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

void dexReadClassDataField(const unsigned char** pData,DexField *pDexField)
{
	pDexField->fieldIdx = readUnsignedLeb128(pData);
    pDexField->accessFlags = readUnsignedLeb128(pData);
   
}

void dexReadClassDataMethod(const unsigned char** pData,DexMethod *pDexMethod)
{
	pDexMethod->methodIdx = readUnsignedLeb128(pData);
	pDexMethod->accessFlags = readUnsignedLeb128(pData);
	pDexMethod->codeOff = readUnsignedLeb128(pData);
}

unsigned char* dexWriteClassDataMethod(unsigned char* ptr, DexMethod *pDexMethod)
{
	ptr = writeUnsignedLeb128(ptr, pDexMethod->methodIdx);
	ptr = writeUnsignedLeb128(ptr, pDexMethod->accessFlags);
	ptr = writeUnsignedLeb128(ptr, pDexMethod->codeOff);
	return ptr;
}

static void dexComputeSHA1Digest(const unsigned char* data, size_t length, unsigned char digest[])
{
    SHA1Context sha;   
	int  err;  
	err = SHA1Reset(&sha);
	if (err)   
	{   
		printf("SHA1Reset Error %d.\n", err );   
		return;    /* out of for j loop */   
	} 
	err = SHA1Input(&sha, data, length);
	if (err)
	{
		printf("SHA1Input Error %d.\n", err );   
		return;  
	}
	err = SHA1Result(&sha, digest);
	if (err)   
	{   
		printf("SHA1Result Error %d, could not compute message digest.\n", err );  
		return; 
	} else
	{
		printf("Signature: ");
		for (int i = 0; i < 20; i++)
		{
			printf("%02X ", digest[i]);
		}
		printf("\n");
	}
}



unsigned int adler32(unsigned char *data, size_t len) /* where data is the location of the data in physical memory and
                                                       len is the length of the data in bytes */
{
    unsigned int a = 1, b = 0;
    int index;

    /* Process each byte of the data in order */
    for (index = 0; index < len; ++index)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}




