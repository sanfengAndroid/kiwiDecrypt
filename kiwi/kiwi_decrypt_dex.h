#ifndef KIWI_DECRYPT_DEX
    #define KIWI_DECRYPT_DEX 
    #include"sha1.h"
    #include "dexFile.h"
    #include"dexClass.h"
    #include"stdint.h"

    unsigned int handle_dex(DexHeader *pHeader, size_t dexLength, char *decrypt_data, unsigned int *ptr_method_id_item, unsigned int *ptr_real_bytecode_off, int num);
    void dexReadClassDataHeader(const unsigned char** pData,DexClassDataHeader *pHeader);
    void dexReadClassDataField(const unsigned char** pData,DexField *pDexField);
 
   
    void dexReadClassDataMethod(const unsigned char** pData,DexMethod *pDexMethod);
    int isEncryptFunction(unsigned int method_id_item, unsigned int *method_id_item_array, int num);
    unsigned char* dexWriteClassDataMethod(unsigned char* ptr, DexMethod *pDexMethod);
    static void dexComputeSHA1Digest(const unsigned char* data, size_t length, unsigned char digest[]);
    unsigned int adler32(unsigned char *data, size_t len);




    unsigned char* writeUnsignedLeb128(unsigned char* ptr, unsigned int data)
    {
        while (1) {
            unsigned char out = data & 0x7f;
            if (out != data) {
                *ptr++ = out | 0x80;
                data >>= 7;
            } else {
                *ptr++ = out;
                break;
            }
        }
    
        return ptr;
    }

    int readUnsignedLeb128(const unsigned char** pStream) {
        const unsigned char* ptr = *pStream;
        int result = *(ptr++);
    
        if (result > 0x7f) {
            int cur = *(ptr++);
            result = (result & 0x7f) | ((cur & 0x7f) << 7);
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 14;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= (cur & 0x7f) << 21;
                    if (cur > 0x7f) {
                        /*
                         * Note: We don't check to see if cur is out of
                         * range here, meaning we tolerate garbage in the
                         * high four-order bits.
                         */
                        cur = *(ptr++);
                        result |= cur << 28;
                    }
                }
            }
        }
    
        *pStream = ptr;
        return result;
    }














#endif