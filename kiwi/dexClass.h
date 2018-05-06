
#ifndef _LIBDEX_DEXCLASS
#define _LIBDEX_DEXCLASS

/* expanded form of a class_data_item header */
typedef struct DexClassDataHeader {
    unsigned int staticFieldsSize;
    unsigned int instanceFieldsSize;
    unsigned int directMethodsSize;
    unsigned int virtualMethodsSize;
} DexClassDataHeader;

/* expanded form of encoded_field */
typedef struct DexField {
    unsigned int fieldIdx;    /* index to a field_id_item */
    unsigned int accessFlags;
} DexField;

/* expanded form of encoded_method */
typedef struct DexMethod {
    unsigned int methodIdx;    /* index to a method_id_item */
    unsigned int accessFlags;
    unsigned int codeOff;      /* file offset to a code_item */
} DexMethod;


typedef struct DexClassData {
    DexClassDataHeader header;
    DexField*          staticFields;
    DexField*          instanceFields;
    DexMethod*         directMethods;
    DexMethod*         virtualMethods;
} DexClassData;




#endif
