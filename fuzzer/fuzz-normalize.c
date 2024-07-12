#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "unicode/ucnv.h"
#include "unicode/unorm2.h"

lua_State *L;

/* Adapted from mb_utf8_to_wchar (from the PHP codebase) */
static bool php_mbstring_check_utf8(unsigned char *in, size_t in_len)
{
	unsigned char *p = in, *e = p + in_len;

	while (p < e) {
		unsigned char c = *p++;

		if (c < 0x80) {
			/* do nothing */
		} else if (c >= 0xC2 && c <= 0xDF) { /* 2 byte character */
			if (p < e) {
				unsigned char c2 = *p++;
				if ((c2 & 0xC0) != 0x80) {
					return false;
				}
			} else {
				return false;
			}
		} else if (c >= 0xE0 && c <= 0xEF) { /* 3 byte character */
			if ((e - p) >= 2) {
				unsigned char c2 = *p++;
				unsigned char c3 = *p++;
				if ((c2 & 0xC0) != 0x80 || (c == 0xE0 && c2 < 0xA0) || (c == 0xED && c2 >= 0xA0)) {
					return false;
				} else if ((c3 & 0xC0) != 0x80) {
					return false;
				}
			} else {
				return false;
			}
		} else if (c >= 0xF0 && c <= 0xF4) { /* 4 byte character */
			if ((e - p) >= 3) {
				unsigned char c2 = *p++;
				unsigned char c3 = *p++;
				unsigned char c4 = *p++;
				/* If c == 0xF0 and c2 < 0x90, then this is an over-long code unit; it could have
				 * fit in 3 bytes only. If c == 0xF4 and c2 >= 0x90, then this codepoint is
				 * greater than U+10FFFF, which is the highest legal codepoint */
				if ((c2 & 0xC0) != 0x80 || (c == 0xF0 && c2 < 0x90) || (c == 0xF4 && c2 >= 0x90)) {
					return false;
				} else if ((c3 & 0xC0) != 0x80) {
					return false;
				} else if ((c4 & 0xC0) != 0x80) {
					return false;
				}
			} else {
				return false;
			}
		} else {
			return false;
		}
	}

	return true;
}

/* Adapted from source code for PostgreSQL ICU extension */
static int32_t icu_to_uchar(UConverter *icu_converter, UChar **buff_uchar, const char *buff, int32_t nbytes)
{
	UErrorCode status = U_ZERO_ERROR;
	int32_t len_uchar = ucnv_toUChars(icu_converter, NULL, 0, buff, nbytes, &status);
	if (U_FAILURE(status) && status != U_BUFFER_OVERFLOW_ERROR) {
		printf("Error from ucnv_toUChars: %s\n", u_errorName(status));
		assert(0);
	}

	*buff_uchar = (UChar *) malloc((len_uchar + 1) * sizeof(**buff_uchar));

	status = U_ZERO_ERROR;
	len_uchar = ucnv_toUChars(icu_converter, *buff_uchar, len_uchar + 1,buff, nbytes, &status);
	if (U_FAILURE(status)) {
		printf("Error from ucnv_toUChars: %s\n", u_errorName(status));
		assert(0);
	}

	return len_uchar;
}

static int32_t icu_from_uchar(UConverter *icu_converter, char **result, const UChar *buff_uchar, int32_t len_uchar)
{
	UErrorCode status = U_ZERO_ERROR;
	uint32_t len_result = ucnv_fromUChars(icu_converter, NULL, 0, buff_uchar, len_uchar, &status);
	if (U_FAILURE(status) && status != U_BUFFER_OVERFLOW_ERROR)
		assert(0);

	*result = (char *) malloc(len_result + 1);

	status = U_ZERO_ERROR;
	len_result = ucnv_fromUChars(icu_converter, *result, len_result + 1, buff_uchar, len_uchar, &status);
	if (U_FAILURE(status))
		assert(0);

	return len_result;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	/*
	printf("Input (%zu): ", Size);
	for (unsigned int i = 0; i < Size; i++)
		printf("%02x ", Data[i]);
	printf("\n");
	*/

	/* We can only compare with the results from ICU if the entire string was valid UTF-8;
	 * ICU won't even allow us to check whether the string is NFC unless it's valid UTF-8 */
	bool valid_utf8 = php_mbstring_check_utf8((unsigned char*)Data, Size);

	UChar *ubuff = NULL;
	int32_t usize = 0;
	UConverter *icu_converter = NULL;

	if (valid_utf8) {
		UErrorCode errcode = U_ZERO_ERROR;
		icu_converter = ucnv_open("utf8", &errcode);
		if (U_FAILURE(errcode)) {
			printf("Error from ucnv_open: %s\n", u_errorName(errcode));
			assert(0);
		}
		usize = icu_to_uchar(icu_converter, &ubuff, (const char*)Data, Size);
	}

	lua_getglobal(L, "utf8");
	lua_getfield(L, -1, "isnfc");
	lua_pushlstring(L, (const char*)Data, Size);
	int err = lua_pcall(L, 1, 1, 0);

	if (err) {
		/* utf8.isnfc raised an error */
		assert(!valid_utf8);
	} else {
		assert(lua_isboolean(L, -1));
		int was_nfc = lua_toboolean(L, -1);

		/* If the string was not NFC, we cannot assume that the string is valid UTF-8,
		 * even if no error was raised... if utf8.isnfc notices that the string is not NFC,
		 * it will immediately return false and will not check whether the trailing portion
		 * is valid UTF-8 or not */
		assert(!was_nfc || valid_utf8);

		if (valid_utf8) {
			UErrorCode errcode = U_ZERO_ERROR;
			const UNormalizer2 *norm = unorm2_getNFCInstance(&errcode);
			assert(!U_FAILURE(errcode));
			UBool was_actually_nfc = unorm2_isNormalized(norm, ubuff, usize, &errcode);
			assert(!U_FAILURE(errcode));

			/*
			printf("lua-utf8, is the input NFC? %s\n", was_nfc ? "yes" : "no");
			printf("ICU, is the input NFC?      %s\n", was_actually_nfc ? "yes" : "no");
			*/

			assert(was_nfc == was_actually_nfc);
		}
	}

	lua_getglobal(L, "utf8");
	lua_getfield(L, -1, "normalize_nfc");
	lua_pushlstring(L, (const char*)Data, Size);
	err = lua_pcall(L, 1, 2, 0);

	if (err) {
		/* utf8.nfc_normalize raised an error */
		assert(!valid_utf8);
	} else {
		assert(lua_isboolean(L, -1));
		int was_already_nfc = lua_toboolean(L, -1);

		assert(lua_isstring(L, -2));
		const char *str = lua_tostring(L, -2);
		size_t str_len = lua_objlen(L, -2);

		assert(valid_utf8 || !was_already_nfc);

		if (valid_utf8) {
			UErrorCode errcode = U_ZERO_ERROR;
			const UNormalizer2 *norm = unorm2_getNFCInstance(&errcode);
			assert(!U_FAILURE(errcode));

			uint32_t dest_size = 3 * usize; /* Maximum size which string could possibly expand to as NFC */
			UChar *dest = malloc(dest_size * sizeof(UChar));

			uint32_t dest_len = unorm2_normalize(norm, ubuff, usize, dest, dest_size, &errcode);
			assert(!U_FAILURE(errcode));

			/* Convert NFC codepoints to UTF-8 bytes */
			char *bytes = NULL;
			uint32_t byte_len = icu_from_uchar(icu_converter, &bytes, dest, dest_len);

			/*
			printf("lua-utf8 (%zu): ", str_len);
			for (unsigned int i = 0; i < str_len; i++)
				printf("%02x ", (uint8_t)str[i]);
			printf("\n");
			printf("ICU      (%u): ", byte_len);
			for (unsigned int i = 0; i < byte_len; i++)
				printf("%02x ", (uint8_t)bytes[i]);
			printf("\n");
			*/

			assert(byte_len == str_len);
			assert(strncmp(str, bytes, str_len) == 0);

			free(dest);
			free(bytes);
		}
	}

	lua_settop(L, 0); // clear Lua stack

	free(ubuff);
	if (icu_converter)
		ucnv_close(icu_converter);

	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	L = luaL_newstate();
	luaL_openlibs(L);
	lua_getglobal(L, "require");
	lua_pushstring(L, "lua-utf8");
	lua_call(L, 1, 1);
	lua_setglobal(L, "utf8");
	return 0;
}
