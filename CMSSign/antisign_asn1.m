/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "header/antisign_asn1.h"


//void
//dump_token(const asn1_token_t *token, uint8_t depth, void *ctx) {
//	(void)ctx;
//
//	const asn1_type_t *type = &token->type;
//
//	char mark = (type->encoding == ASN1_ENCODING_PRIMITIVE) ? '-' : '*';
//	char buf[256];
//
//	char *suffix = "";
//	if (asn1_type_to_string(buf, sizeof(buf), type) >= sizeof(buf)) {
//		suffix = "...";
//	}
//	printf("%*s%c %s%s", depth * 2, "", mark, buf, suffix);
//
//	if (type->encoding == ASN1_ENCODING_CONSTRUCTED) {
//		printf("\n");
//	} else if (type->cls == ASN1_CLASS_UNIVERSAL) {
//		switch (type->tag) {
//		case ASN1_TAG_T61STRING:
//		case ASN1_TAG_IA5STRING:
//		case ASN1_TAG_UTF8STRING:
//		case ASN1_TAG_VISIBLESTRING:
//		case ASN1_TAG_PRINTABLESTRING:
//			if (asn1_string(token, buf, sizeof(buf)).errn != ASININE_OK) {
//				printf(" <INVALID STR>\n");
//				break;
//			}
//
//			printf(" '%s'\n", buf);
//			break;
//
//		case ASN1_TAG_INT: {
//			asn1_word_t value;
//
//			if (asn1_int(token, &value).errn != ASININE_OK) {
//				printf(" <INVALID INT>\n");
//				break;
//			}
//
//			printf(" %" PRIdPTR "\n", value);
//			break;
//		}
//
//		case ASN1_TAG_OID: {
//			asn1_oid_t oid;
//
//			if (asn1_oid(token, &oid).errn != ASININE_OK) {
//				printf(" <INVALID OID>\n");
//				break;
//			}
//
//			if (asn1_oid_to_string(buf, sizeof(buf), &oid) >= sizeof(buf)) {
//				printf(" <TOO LONG>\n");
//				break;
//			}
//
//			printf(" %s\n", buf);
//			break;
//		}
//
//		case ASN1_TAG_UTCTIME:
//		case ASN1_TAG_GENERALIZEDTIME: {
//			asn1_time_t time;
//
//			if (asn1_time(token, &time).errn != ASININE_OK) {
//				printf(" <INVALID TIME>\n");
//				break;
//			}
//
//			if (asn1_time_to_string(buf, sizeof buf, &time) >= sizeof(buf)) {
//				printf(" <TOO LONG>\n");
//				break;
//			}
//
//			printf(" %s\n", buf);
//			break;
//		}
//
//		case ASN1_TAG_OCTETSTRING:
//			printf("\n");
//			hexdump(token->data, token->length, depth);
//			break;
//
//		case ASN1_TAG_BOOL: {
//			bool value;
//
//			if (asn1_bool(token, &value).errn != ASININE_OK) {
//				printf(" <INVALID BOOL>\n");
//				break;
//			}
//
//			printf(" %s\n", value ? "True" : "False");
//			break;
//		}
//
//		case ASN1_TAG_NULL:
//			printf("\n");
//			break;
//        case ASN1_TAG_EOC:
//            printf("\n");
//            break;
//		default:
//			printf(" <NOT IMPLEMENTED> : tag = %d\n", type->tag);
//			break;
//		}
//	} else {
//		printf("\n  cls = %d, tag = %d \n", type->cls, type->tag);
//		hexdump(token->data, token->length, depth);
//	}
//}

//int
//main(int argc, const char *argv[]) {
//	const uint8_t *contents;
//	size_t length;
//
//	if (argc < 2) {
//		printf("%s <file>\n", argv[0]);
//		return 1;
//	}
//
//	contents = load(argv[1], &length);
//	if (contents == NULL) {
//		return 1;
//	}
//
//	asn1_parser_t parser;
//	asn1_init(&parser, contents, length);
//
//	asinine_err_t err = asn1_tokens(&parser, NULL, dump_token);
//	if (err.errn != ASININE_OK) {
//		fprintf(stderr, "Failed: %s\n", asinine_strerror(err));
//		return 2;
//	}
//
//	return 0;
//}
