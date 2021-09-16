//
//  cms.c
//  antisdk
//
//  Created by 郭浩 on 2020/4/1.
//  Copyright © 2020 郭浩. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "header/antisign_dsl.h"
#include "header/antisign_cms.h"
#include "header/antisign_x509.h"
#include "header/antisign_errors.h"


asinine_err_t
cms_oid_totype(asn1_oid_t* oid, cms_content_type* t) {
    if(asn1_oid_cmp(oid, &((asn1_oid_t)ASN1_OID(1, 2, 840, 113549, 1, 7, 2))) == 0 ||
       asn1_oid_cmp(oid, &((asn1_oid_t)ASN1_OID(1, 2, 840, 113549, 1, 7, 1))) == 0) {
        *t = CMS_CONTENT_SIGNEDDATA;
        return ERROR(ASININE_OK, NULL);
    }
    return ERROR(ASININE_ERR_INVALID, ASLOG("cms: unsupport content type"));
}

asinine_err_t
cms_asn1_get_next(asn1_parser_t *parser) {
    asn1_next(parser);
    if (parser->token.type.encoding == ASN1_ENCODING_CONSTRUCTED) {
        RETURN_ON_ERROR(asn1_push(parser));
    }

    while (asn1_eof(parser)) {
        RETURN_ON_ERROR(asn1_pop(parser));
    }
    return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parse_content(asn1_parser_t *parser, CMS_ContentInfo *cms) {
    *cms                     = (CMS_ContentInfo){0};
    const asn1_token_t *token = &parser->token;
    // CMS_CONTENT
    NEXT_TOKEN(parser);   //初始化第一个token,开始指向seq
    
    NEXT_TOKEN(parser);    // cms证书第一个seq不定长编码，直接next，下一个为oid, asn1_push_seq(parser);
  //  NEXT_TOKEN(parser);
    if (asn1_is_oid(token)) {
        asn1_oid_t content_type;

        RETURN_ON_ERROR(asn1_oid(token, &content_type));
        cms_content_type t;
        if(cms_oid_totype(&content_type, &t).errn != ASININE_OK) {
            return ERROR(ASININE_ERR_INVALID, ASLOG("CMS_ContentInfo: unsupport content type"));
        }
        cms->contentType = t;
        NEXT_TOKEN(parser);
       // 指向 seq数组
    } else {
        return ERROR(ASININE_ERR_INVALID, ASLOG("CMS_ContentInfo: invalid content type"));
    }
    // CMS_SignedData
    RETURN_ON_ERROR(cms_parse_signData(parser, &cms->signedData));

    return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parse_signData(asn1_parser_t *parser, CMS_SignedData* signData) {
    const asn1_token_t *token = &parser->token;

    
    //RETURN_ON_ERROR(asn1_push_seq(parser));
    if (asn1_is(token, ASN1_CLASS_CONTEXT, 0, ASN1_ENCODING_CONSTRUCTED)) {

        NEXT_TOKEN(parser);  // seq不定长
        NEXT_TOKEN(parser);   //seq不定长
        
        asn1_word_t version;
        if (!asn1_is_int(token)) {
            return ERROR(ASININE_ERR_INVALID, ASLOG("CMS_SignedData: not int"));
        }

        RETURN_ON_ERROR(asn1_int(token, &version));

        if (version != X509_V2 && version != X509_V3) {
            return ERROR(ASININE_ERR_INVALID, ASLOG("cert: unknown version"));
        }
        signData->version = version;
        //set
        //cms_asn1_get_next(parser);
    } else {
        return ERROR(ASININE_ERR_INVALID, ASLOG("CMS_SignedData: invalid version"));
    }
    NEXT_TOKEN(parser);  //set
    asn1_push(parser);   //set定长,需要push
    
    // digestAlgorithms
    //cms_asn1_get_next(parser);
    RETURN_ON_ERROR(cms_parse_signature_algo(parser, &signData->digestAlgorithms));
    
    asn1_pop(parser);
    NEXT_TOKEN(parser);
    
    // content_info
    RETURN_ON_ERROR(cms_parse_content_info(parser, signData));

    // certs
    RETURN_ON_ERROR(cms_parce_certificates(parser, &signData->certificates));

    //signedattrs
    RETURN_ON_ERROR(cms_parse_signedInfo(parser, &signData->signerInfos));
    
    return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parse_signature(asn1_parser_t *parser, raw_data_t *signature) {
    const asn1_token_t *const token = &parser->token;
    
   // RETURN_ON_ERROR(asn1_push(parser));
    
    
    if (!asn1_is_octetstring(token)) {
        return ERROR(ASININE_ERR_INVALID, ASLOG("Signature: not a octertstring"));
    }
    
    signature->data = token->data;
    signature->num = token->length;
    return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parse_signature_algo(asn1_parser_t *parser, x509_signature_t *digestAlgorithms) {
    const asn1_token_t *const token = &parser->token;
    
    asn1_push_seq(parser);  //seq定长
    
    NEXT_TOKEN(parser);  // oid
    if (!asn1_is_oid(token)) {
        return ERROR(ASININE_ERR_INVALID, ASLOG("digestAlgorithms: not a oid"));
    }

    asn1_oid_t oid;
    RETURN_ON_ERROR(asn1_oid(token, &oid));

    const signature_lookup_t *result = find_signature_algorithm(&oid);
    if (result == NULL) {
        return ERROR(ASININE_ERR_UNSUPPORTED, ASLOG("digestAlgorithms: unknown algorithm"));
    }
    
    digestAlgorithms->algorithm = result->algorithm;
    RETURN_ON_ERROR(result->parser(parser, digestAlgorithms));
   
    RETURN_ON_ERROR(asn1_pop(parser));
    
    return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parse_content_info(asn1_parser_t *parser, CMS_SignedData *signedData) {
    const asn1_token_t *token = &parser->token;

       NEXT_TOKEN(parser);  //seq不定长
       if (asn1_is_oid(token)) {
           asn1_oid_t content_type;

//           RETURN_ON_ERROR(asn1_push(parser));
//           NEXT_TOKEN(parser);
           if (!asn1_is_oid(token)) {
               return ERROR(ASININE_ERR_INVALID, ASLOG("content_info: not a oid"));
           }

           RETURN_ON_ERROR(asn1_oid(token, &content_type));
           cms_content_type t;
           if(cms_oid_totype(&content_type, &t).errn != ASININE_OK) {
               return ERROR(ASININE_ERR_INVALID, ASLOG("cms: unsupport content type"));
           }

           signedData->encapContentInfo = t;
           NEXT_TOKEN(parser);  //这里过滤了EOC
       } else {
           return ERROR(ASININE_ERR_INVALID, ASLOG("cms: content type error"));
       }

       return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parce_certificates(asn1_parser_t *parser, CMS_x509_cert *certs) {
    //const asn1_token_t *token = &parser->token;
    *certs                     = (CMS_x509_cert){0};
    //证书的集合
    asn1_push(parser);  //这里是定长
    
    do{
        NEXT_TOKEN(parser);   //第一个证书的seq
        x509_cert_t cert;
        RETURN_ON_ERROR(x509_parse_cert(parser, &cert));
        certs->certs[certs->num] = cert;
        certs->num += 1;
    }
    while (!asn1_eof(parser));
    RETURN_ON_ERROR(asn1_pop(parser));
    return asn1_next(parser);
}

asinine_err_t
cms_parse_signedInfo(asn1_parser_t *parser, CMS_SignerInfo* signedInfo) {
    const asn1_token_t *token = &parser->token;
    
    RETURN_ON_ERROR(asn1_push(parser));  //定长 set
    NEXT_TOKEN(parser);
    RETURN_ON_ERROR(asn1_push(parser));  //定长 seq
    NEXT_TOKEN(parser);
    asn1_word_t version;
    if (!asn1_is_int(token)) {
        return ERROR(ASININE_ERR_INVALID, ASLOG("CMS_SignerInfo: not a int"));
    }
    
    RETURN_ON_ERROR(asn1_int(token, &version));
    
    signedInfo->version = version;
    
    NEXT_TOKEN(parser);
    
    RETURN_ON_ERROR(asn1_push(parser));
    //NEXT_TOKEN(parser);
    RETURN_ON_ERROR(x509_parse_name(parser, &signedInfo->sid));
    NEXT_TOKEN(parser);
    ;
    //TODO serial number
    RETURN_ON_ERROR(asn1_pop(parser));
    
    //digestAlgorithm
    RETURN_ON_ERROR(cms_parse_signature_algo(parser, &signedInfo->digestAlgorithm));
    
    NEXT_TOKEN(parser);
    
    //signedAttr
    
    token = &parser->token;
     
    if(token->type.encoding == ASN1_ENCODING_CONSTRUCTED)
    {
        //记录 signAttr的原始数据
        signedInfo->signedAttrsRowData.data = token->data;
        signedInfo->signedAttrsRowData.num = token->length;
    }
   
    RETURN_ON_ERROR(cms_parse_signedAttr(parser, &signedInfo->signedAttrs));
    
    //签名算法
    //printf("psrse signatureAlgorithm\n");
    RETURN_ON_ERROR(cms_parse_signature_algo(parser, &signedInfo->signatureAlgorithm));
    //签名值
    NEXT_TOKEN(parser);
    //printf("psrse signature\n");
    RETURN_ON_ERROR(cms_parse_signature(parser, &signedInfo->signature));
    
    RETURN_ON_ERROR(asn1_pop(parser));
    RETURN_ON_ERROR(asn1_pop(parser));
    return ERROR(ASININE_OK, NULL);
}

asinine_err_t
cms_parse_signedAttr(asn1_parser_t *parser, x509_name_t *name) {
    const asn1_token_t *token = &parser->token;

    *name = (x509_name_t){0};
    
    RETURN_ON_ERROR(asn1_push(parser));  //定长seq
    
    while (!asn1_eof(parser) && name->num < X509_MAX_RDNS) {
        NEXT_TOKEN(parser);  //定长seq
        //NEXT_TOKEN(parser);
        if (!asn1_is_sequence(token)) {
            return ERROR(ASININE_ERR_INVALID, ASLOG("signedAttr: not  squence"));
        }

      //  RETURN_ON_ERROR(asn1_push_seq(parser));
        RETURN_ON_ERROR(asn1_push(parser));   //定长seq
        // Get identifiying key (OID)
        NEXT_TOKEN(parser);  // oid

        if (!asn1_is_oid(token)) {
            return ERROR(ASININE_ERR_INVALID, ASLOG("signedAttr: not a oid"));
        }

        asn1_oid_t oid;
        RETURN_ON_ERROR(asn1_oid(token, &oid));
        x509_rdn_type_t type = find_rdn_type(&oid);
        if (type == X509_RDN_INVALID) {
            return ERROR(ASININE_ERR_UNSUPPORTED, ASLOG("signedAttr: unknown RDN"));
        }

        // Get set value
        NEXT_TOKEN(parser);  //定长set
        
        if (!asn1_is_set(token)) {
            return ERROR(ASININE_ERR_INVALID, ASLOG("signedAttr: not a set"));
        }
        RETURN_ON_ERROR(asn1_push(parser));
        
        NEXT_TOKEN(parser);
        if(token->type.encoding == ASN1_ENCODING_CONSTRUCTED){
            // TODO 可能是多RDB ,1.2.840.113635.100.9.2   //set下可能有多个seq
        //    RETURN_ON_ERROR(asn1_push(parser));
        //    NEXT_TOKEN(parser);
            if(type == X509_RDN_HASH_Algorithm)   //HASH 算法：包含 SHA256 和 SHA1 两个HASH 值
            {
                RETURN_ON_ERROR(asn1_push(parser));  // 定长seq
                while (!asn1_eof(parser))
                {
                    NEXT_TOKEN(parser);  // oid
                    RETURN_ON_ERROR(asn1_oid(token, &oid));
                    x509_rdn_type_t type = find_rdn_type(&oid);
                    
                    if(type == X509_RDN_HASH_SHA256 || type == X509_RDN_HASH_SHA1)
                    {
                        NEXT_TOKEN(parser);  //HASH值
                        
                        name->rdns[name->num].type  = type;
                        name->rdns[name->num].value = *token;
                        name->num++;
                    }
                    
                    RETURN_ON_ERROR(asn1_pop(parser));
                    if(!asn1_eof(parser)){
                        NEXT_TOKEN(parser);
                        RETURN_ON_ERROR(asn1_push(parser));  // 定长seq
                    } 
                }
                
            }
            else
            {   // FIXME
                while (!asn1_eof(parser))
                {
                    NEXT_TOKEN(parser);
                }
            }
           
         //   RETURN_ON_ERROR(asn1_pop(parser));
        }
        else
        {
            //NEXT_TOKEN(parser);
            name->rdns[name->num].type  = type;
            name->rdns[name->num].value = *token;
            name->num++;
          
        }
        
        RETURN_ON_ERROR(asn1_pop(parser));
        // End of RDN
        RETURN_ON_ERROR(asn1_pop(parser));
        
        //NEXT_TOKEN(parser); //  下一个后 parse已经是eof,因此next放在开始
    }
    
    if (!asn1_eof(parser)) {
        return ERROR(ASININE_ERR_MEMORY, ASLOG("name: too many RDNs"));
    }
    
   
    RETURN_ON_ERROR(asn1_pop(parser));
     
    x509_sort_name(name);

    return ERROR(ASININE_OK, NULL);
}

