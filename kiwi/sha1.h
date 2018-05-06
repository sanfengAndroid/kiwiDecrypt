#ifndef _SHA1_H_ 
#define _SHA1_H_ 
 
#include "stdint.h" 
 
 
#ifndef _SHA_enum_ 
#define _SHA_enum_ 
enum 
{ 
    shaSuccess = 0, 
    shaNull,            /* 空指示参量 */ 
    shaInputTooLong,    /* 输入数据太长提示 */ 
    shaStateError       /* called Input after Result --以输入结果命名之 */ 
}; 
#endif 
#define SHA1HashSize 20 
 
/* 
 *  以下这种结构将会控制上下文消息 for the SHA-1 
 *  hashing operation 
 */ 
typedef struct SHA1Context 
{ 
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */ 
 
    uint32_t Length_Low;            /* Message length in bits      */ 
    uint32_t Length_High;           /* Message length in bits      */ 
 
                               /* Index into message block array   */ 
    int_least16_t Message_Block_Index; 
    uint8_t Message_Block[64];      /* 512-bit message blocks      */ 
 
    int Computed;               /* Is the digest computed?         */ 
    int Corrupted;             /* Is the message digest corrupted? */ 
} SHA1Context; 
 
/* 
 *  函数原型 
 */ 
int SHA1Reset(  SHA1Context *); 
int SHA1Input(  SHA1Context *, 
                const uint8_t *, 
                unsigned int); 
int SHA1Result( SHA1Context *, 
                uint8_t Message_Digest[SHA1HashSize]); 
 
#endif /*_SHA1_H_*/ 