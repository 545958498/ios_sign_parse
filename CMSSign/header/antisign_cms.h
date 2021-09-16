
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "antisign_x509.h"
#include "antisign_asn1.h"


#define CMS_MAX_CERTS 8

typedef enum cms_content_t {
    CMS_CONTENT_INVALID = 0,
    CMS_CONTENT_SIGNEDDATA,
    CMS_CONTENT_ENVELOPEDDATA,
    CMS_CONTENT_DIGESTEDDATA,
    CMS_CONTENT_ENCRYPTEDDATA,
    CMS_CONTENT_AUTHENTICATEDDATA,
    CMS_CONTENT_COMPRESSEDDATA,
    CMS_CONTENT_OTHER
} cms_content_type;

typedef struct raw_data {
    const uint8_t *data;
    size_t num;
} raw_data_t;

typedef struct CMS_SignerInfo_st {
    long version;
    x509_name_t sid;
    x509_signature_t digestAlgorithm;  //哈希算法， 对 signedAttrs 内容计算哈希使用的算法
    x509_name_t signedAttrs;           //属性信息，包括对CodeDirectory的内容的哈希值
    raw_data_t signedAttrsRowData;           //属性信息，包括对CodeDirectory的内容的哈希值
    x509_signature_t signatureAlgorithm; // 对 signedAttrs 计算哈希后，再使用私钥签名使用的算法
    raw_data_t signature;              // 上述签名后的签名值
//    X509_ATTRIBUTE *unsignedAttrs;
    /* Signing certificate and key */
//    X509 *signer;
 //   EVP_PKEY *pkey;
}CMS_SignerInfo;

typedef struct CMS_x509_cert_t {
    uint8_t num;
    x509_cert_t certs[CMS_MAX_CERTS];
}CMS_x509_cert;

typedef struct CMS_SignedData_st {
    long version;
    x509_signature_t digestAlgorithms;
    cms_content_type encapContentInfo;
    CMS_x509_cert certificates;
    CMS_SignerInfo signerInfos;
}CMS_SignedData;

typedef struct CMS_ContentInfo_st {
      cms_content_type contentType;
//    union {
//        ASN1_OCTET_STRING *data;
//        CMS_SignedData *signedData;
//        CMS_EnvelopedData *envelopedData;
//        CMS_DigestedData *digestedData;
//        CMS_EncryptedData *encryptedData;
//        CMS_AuthenticatedData *authenticatedData;
//        CMS_CompressedData *compressedData;
//        ASN1_TYPE *other;
//        /* Other types ... */
//        void *otherData;
//    } d;
    CMS_SignedData signedData;  //其它z暂不实现
}CMS_ContentInfo;

asinine_err_t
cms_parse_signData(asn1_parser_t *parser, CMS_SignedData* signData);
asinine_err_t
cms_parse_signature_algo(asn1_parser_t *parser, x509_signature_t *signature);
asinine_err_t
cms_parse_content_info(asn1_parser_t *parser, CMS_SignedData *signedData);
asinine_err_t
cms_parce_certificates(asn1_parser_t *parser, CMS_x509_cert *certs);
asinine_err_t
cms_parse_content(asn1_parser_t *parser, CMS_ContentInfo *cms);
asinine_err_t
cms_parse_signedInfo(asn1_parser_t *parser, CMS_SignerInfo* signedInfo);
asinine_err_t
cms_parse_signedAttr(asn1_parser_t *parser, x509_name_t *name);
asinine_err_t
cms_parse_signature(asn1_parser_t *parser, raw_data_t *signature);




#ifdef __cplusplus
}
#endif
