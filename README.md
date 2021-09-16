# CMS签名解析
CMS签名解析，IOS签名段解析

asn1_parser_t parser;
CMS_ContentInfo cms;

asn1_init(&parser, (const uint8_t *)data, (size_t)data_len);

asinine_err_t res = cms_parse_content(&parser, &cms);
