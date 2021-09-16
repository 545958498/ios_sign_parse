/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "asn1.h"

#define X509_MAX_RDNS (13)
#define X509_MAX_ALT_NAMES (128)
#define X509_MAX_ALT_DIRECTORY_NAMES (1)

typedef enum x509_version {
	X509_V1 = 0,
	X509_V2 = 1,
	X509_V3 = 2
} x509_version_t;

typedef enum x509_sig_algo {
	X509_SIGNATURE_INVALID = 0,
	X509_SIGNATURE_MD2_RSA,
	X509_SIGNATURE_MD5_RSA,
	X509_SIGNATURE_SHA1_RSA,
	X509_SIGNATURE_SHA256_RSA,
    X509_SIGNATURE_SHA256,
    X509_SIGNATURE_SHA1,
	X509_SIGNATURE_SHA384_RSA,
	X509_SIGNATURE_SHA512_RSA,
	X509_SIGNATURE_SHA256_ECDSA,
	X509_SIGNATURE_SHA384_ECDSA,
	X509_SIGNATURE_SHA512_ECDSA,
	X509_SIGNATURE_SHA256_DSA,
} x509_sig_algo_t;

typedef struct x509_signature {
	x509_sig_algo_t algorithm;
	const uint8_t *data;
	size_t num;
} x509_signature_t;


typedef struct x509_pubkey_rsa {
	const uint8_t *n;
	size_t n_num;
	const uint8_t *e;
	size_t e_num;
} x509_pubkey_rsa_t;

typedef enum x509_ecdsa_curve {
	X509_ECDSA_CURVE_INVALID = 0,
	X509_ECDSA_CURVE_SECP256R1,
	X509_ECDSA_CURVE_SECP384R1,
	X509_ECDSA_CURVE_SECP521R1,
} x509_ecdsa_curve_t;

typedef struct x509_pubkey_ecdsa {
	const uint8_t *point;
	size_t point_num;
} x509_pubkey_ecdsa_t;

typedef enum x509_pubkey_algo {
	X509_PUBKEY_INVALID = 0,
	X509_PUBKEY_RSA,
	X509_PUBKEY_ECDSA,
} x509_pubkey_algo_t;

typedef union x509_pubkey_params {
	// The null values for any pubkey params must
	// signify an invalid state.
	x509_ecdsa_curve_t ecdsa_curve;
} x509_pubkey_params_t;

typedef struct x509_pubkey {
	x509_pubkey_algo_t algorithm;
	union {
		x509_pubkey_rsa_t rsa;
		x509_pubkey_ecdsa_t ecdsa;
	} key;
} x509_pubkey_t;

/**
 * Key usage flags
 * @note from RFC 5280, p.29
 */
typedef enum x509_keyuse {
	X509_KEYUSE_DIGITAL_SIGNATURE  = (1 << 0),
	X509_KEYUSE_CONTENT_COMMITMENT = (1 << 1),
	X509_KEYUSE_KEY_ENCIPHERMENT   = (1 << 2),
	X509_KEYUSE_DATA_ENCIPHERMENT  = (1 << 3),
	X509_KEYUSE_KEY_AGREEMENT      = (1 << 4),
	X509_KEYUSE_KEY_CERT_SIGN      = (1 << 5),
	X509_KEYUSE_CRL_SIGN           = (1 << 6),
	X509_KEYUSE_ENCIPHER_ONLY      = (1 << 7),
	X509_KEYUSE_DECIPHER_ONLY      = (1 << 8)
} x509_keyuse_t;

typedef enum x509_ext_keyuse {
	X509_EXT_KEYUSE_SERVER_AUTH  = 1,
	X509_EXT_KEYUSE_CLIENT_AUTH  = 2,
	X509_EXT_KEYUSE_CODE_SIGNING = 4,
	X509_EXT_KEYUSE_EMAIL_PROT   = 8,
	X509_EXT_KEYUSE_TIME_STAMP   = 16,
	X509_EXT_KEYUSE_OCSP_SIGN    = 32,
	X509_EXT_KEYUSE_ANY          = 63
} x509_ext_keyuse_t;

typedef enum x509_rdn_type {
	X509_RDN_INVALID,
	X509_RDN_JURISDICTION_COUNTRY,
	X509_RDN_JURISDICTION_STATE_OR_PROVINCE,
	X509_RDN_JURISDICTION_LOCALITY,
    X509_RDN_USERID,  //4
    X509_RDN_CONTENT_TYPE,
    X509_RDN_SIGNTIME,
    X509_RDN_DIGEST_HASH,
    X509_RDN_HASH_Algorithm,
    X509_RDN_HASH_SHA256,
    X509_RDN_HASH_SHA1,
    X509_RDN_MESSAGE_DIGEST,
	X509_RDN_COUNTRY,  //10
	X509_RDN_STATE_OR_PROVINCE,
	X509_RDN_LOCALITY,
	X509_RDN_POSTAL_CODE,
	X509_RDN_STREET_ADDRESS,
	X509_RDN_PO_BOX,
	X509_RDN_BUSINESS_CATEGORY,
	X509_RDN_ORGANIZATION,   //17
	X509_RDN_ORGANIZATIONAL_UNIT,  //18
	X509_RDN_ORGANIZATIONAL_ID,
	X509_RDN_DISTINGUISHED_NAME,
	X509_RDN_DISTINGUISHED_NAME_QUALIFIER,
	X509_RDN_COMMON_NAME,   //22
	X509_RDN_SERIAL_NUMBER,
	X509_RDN_SURNAME,
	X509_RDN_EMAIL,
} x509_rdn_type_t;

typedef struct x509_rdn {
	x509_rdn_type_t type;
	asn1_token_t value;
} x509_rdn_t;

typedef struct x509_name {
	size_t num;
	x509_rdn_t rdns[X509_MAX_RDNS];
} x509_name_t;

typedef enum x509_alt_name_type {
	X509_ALT_NAME_RFC822NAME = 1,
	X509_ALT_NAME_DNSNAME    = 2,
	X509_ALT_NAME_DIRECTORY  = 4,
	X509_ALT_NAME_URI        = 6,
	X509_ALT_NAME_IP         = 7,
} x509_alt_name_type_t;

typedef struct {
	x509_alt_name_type_t type;
	size_t length;
	const uint8_t *data;
} x509_alt_name_t;

typedef struct x509_alt_names {
	size_t num;
	x509_alt_name_t names[X509_MAX_ALT_NAMES];
	size_t directory_num;
	x509_name_t directory[X509_MAX_ALT_DIRECTORY_NAMES];
} x509_alt_names_t;

typedef struct x509_cert {
	x509_version_t version;
	x509_signature_t signature;
	const uint8_t *raw;
	size_t raw_num;
	x509_name_t issuer;
	x509_name_t subject;
	x509_pubkey_t pubkey;
	bool has_pubkey_params;
	x509_pubkey_params_t pubkey_params;
	asn1_time_t valid_from;
	asn1_time_t valid_to;
	x509_alt_names_t subject_alt_names;
	uint16_t key_usage;
	uint8_t ext_key_usage;
	bool is_ca;
	int8_t path_len_constraint;
} x509_cert_t;

ASININE_API asinine_err_t x509_parse_cert(
    asn1_parser_t *parser, x509_cert_t *cert);
ASININE_API asinine_err_t x509_parse_name(
    asn1_parser_t *parser, x509_name_t *name);
ASININE_API asinine_err_t x509_parse_optional_name(
    asn1_parser_t *parser, x509_name_t *name);
ASININE_API asinine_err_t x509_parse_alt_names(
    asn1_parser_t *parser, x509_alt_names_t *alt_names);
ASININE_API asinine_err_t x509_parse_pubkey(asn1_parser_t *parser,
    x509_pubkey_t *pubkey, x509_pubkey_params_t *params, bool *has_params);
ASININE_API void x509_sort_name(x509_name_t *name);
ASININE_API const char *x509_rdn_type_string(x509_rdn_type_t type);
ASININE_API bool x509_name_eq(
    const x509_name_t *a, const x509_name_t *b, const char **err);

typedef asinine_err_t (*x509_validation_cb_t)(const x509_pubkey_t *pubkey,
    x509_pubkey_params_t params, const x509_signature_t *sig,
    const uint8_t *raw, size_t raw_num, void *ctx);

typedef struct x509_path {
	void *ctx;
	x509_pubkey_t public_key;
	x509_pubkey_params_t public_key_parameters;
	x509_name_t issuer_name;
	x509_validation_cb_t cb;
	asn1_time_t now;
	int8_t max_length;
} x509_path_t;

typedef asinine_err_t (*signature_parser_t)(
    asn1_parser_t *, x509_signature_t *);

typedef struct {
    asn1_oid_t oid;
    x509_sig_algo_t algorithm;
    signature_parser_t parser;
} signature_lookup_t;

typedef asinine_err_t (*extension_parser_t)(asn1_parser_t *, x509_cert_t *);

typedef struct {
    asn1_oid_t oid;
    extension_parser_t parser;
} extension_lookup_t;

asinine_err_t parse_optional(asn1_parser_t *, x509_cert_t *);
asinine_err_t parse_extensions(asn1_parser_t *, x509_cert_t *);
asinine_err_t parse_null_or_empty_args(
    asn1_parser_t *, x509_signature_t *);
asinine_err_t parse_empty_args(asn1_parser_t *, x509_signature_t *);
asinine_err_t parse_signature_algo(asn1_parser_t *, x509_signature_t *);
asinine_err_t parse_validity(asn1_parser_t *, x509_cert_t *);

asinine_err_t parse_extn_key_usage(asn1_parser_t *, x509_cert_t *);
asinine_err_t parse_extn_ext_key_usage(asn1_parser_t *, x509_cert_t *);
asinine_err_t parse_extn_basic_constraints(
    asn1_parser_t *, x509_cert_t *);
asinine_err_t
parse_extn_developerSign(asn1_parser_t *parser, x509_cert_t *cert);
asinine_err_t parse_extn_subject_alt_name(
    asn1_parser_t *, x509_cert_t *);
x509_rdn_type_t
find_rdn_type(const asn1_oid_t *oid);
const signature_lookup_t *find_signature_algorithm(const asn1_oid_t *oid);
asinine_err_t _x509_parse_null_or_empty_args(asn1_parser_t *parser);

static const signature_lookup_t signature_algorithms[] = {
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 2), X509_SIGNATURE_MD2_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 4), X509_SIGNATURE_MD5_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 5), X509_SIGNATURE_SHA1_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 1), X509_SIGNATURE_SHA1_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 11), X509_SIGNATURE_SHA256_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(2, 16, 840, 1, 101, 3, 4, 2, 1), X509_SIGNATURE_SHA256,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 3, 14, 3, 2, 26), X509_SIGNATURE_SHA1,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 12), X509_SIGNATURE_SHA384_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 113549, 1, 1, 13), X509_SIGNATURE_SHA512_RSA,
        &parse_null_or_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 4, 3, 2), X509_SIGNATURE_SHA256_ECDSA,
        &parse_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 4, 3, 3), X509_SIGNATURE_SHA384_ECDSA,
        &parse_empty_args,
    },
    {
        ASN1_OID(1, 2, 840, 10045, 4, 3, 3), X509_SIGNATURE_SHA512_ECDSA,
        &parse_empty_args,
    },
    {
        ASN1_OID(2, 16, 840, 1, 101, 3, 4, 3, 2), X509_SIGNATURE_SHA256_DSA,
        &parse_empty_args,
    },
};

static const extension_lookup_t extensions[] = {
    
    {ASN1_OID(2, 5, 29, 15), &parse_extn_key_usage},
    {ASN1_OID(2, 5, 29, 17), &parse_extn_subject_alt_name},
    {ASN1_OID(2, 5, 29, 19), &parse_extn_basic_constraints},
    {ASN1_OID(2, 5, 29, 37), &parse_extn_ext_key_usage},
    {ASN1_OID(1, 2, 840, 113635, 100, 6, 1, 2), &parse_extn_developerSign},
    {ASN1_OID(1, 2, 840, 113635, 100, 6, 1, 12), &parse_extn_developerSign},
    {ASN1_OID(1, 2, 840, 113635, 100, 6, 1, 4),  &parse_extn_developerSign},
    
};


ASININE_API asinine_err_t x509_find_issuer(
    asn1_parser_t *parser, const x509_cert_t *cert, x509_cert_t *issuer);

ASININE_API void x509_path_init(x509_path_t *path, const x509_cert_t *anchor,
    const asn1_time_t *now, x509_validation_cb_t cb, void *ctx);

ASININE_API asinine_err_t x509_path_add(
    x509_path_t *path, const x509_cert_t *cert);

ASININE_API asinine_err_t x509_path_end(
    x509_path_t *path, const x509_cert_t *cert);

#ifdef __cplusplus
}
#endif
