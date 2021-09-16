/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#define ERROR(e, r) \
	(asinine_err_t) { .errn = e, .reason = r }

#define RETURN_ON_ERROR(expr) \
	do { \
		asinine_err_t ret_##__LINE__ = expr; \
		if (ret_##__LINE__.errn != ASININE_OK) { \
			return ret_##__LINE__; \
		} \
	} while (0)


#if (defined(DEBUG) && DEBUG == 1)
#define ASLOG(str) str
#define ASPLOG(str, str1) str#str1
#else
#define ASLOG(str) ""
#define ASPLOG(str, str1) str1
#endif

#define asn_assert_nonull(var) if(var == NULL)return;
#define asn_assert_nonull_bool(var) if(var == NULL){return false;}

