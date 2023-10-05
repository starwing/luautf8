#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "unicode/ucnv.h"
#include "unicode/ubrk.h"

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

/* From PHP codebase */
const unsigned char mblen_table_utf8[] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	4, 4, 4, 4, 4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

const size_t utf16_code_unit_len(const unsigned char *s, size_t byte_len) {
	const unsigned char *e = s + byte_len;
	size_t result = 0;
	while (s < e) {
		unsigned char c = *s;
		s += mblen_table_utf8[c];
		result++;
		if (c >= 0xF0 && c <= 0xF4)
			result++; /* 4-byte UTF-8 characters will take 2 UTF-16 code units */
	}
	return result;
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	/*
	printf("(%zu): ", Size);
	for (unsigned int i = 0; i < Size; i++)
		printf("%02x ", Data[i]);
	printf("\n");
	*/

	/* We can only compare with the results from ICU if the entire string was valid UTF-8;
	 * ICU needs to convert the entire string to codepoints before operationg on it,
	 * and it can only do that if it's valid UTF-8 */
	bool valid_utf8 = php_mbstring_check_utf8((unsigned char*)Data, Size);

	UChar *ubuff = NULL;
	int32_t usize = 0;
	UConverter *icu_converter = NULL;
	UBreakIterator *bi = NULL;
	uint32_t p = 0;

	if (valid_utf8) {
		UErrorCode errcode = U_ZERO_ERROR;
		icu_converter = ucnv_open("utf8", &errcode);
		if (U_FAILURE(errcode)) {
			printf("Error from ucnv_open: %s\n", u_errorName(errcode));
			assert(0);
		}
		usize = icu_to_uchar(icu_converter, &ubuff, (const char*)Data, Size);
		errcode = U_ZERO_ERROR;

		/*
		printf("UTF-16 code units from ICU: (%d): ", usize);
		for (unsigned int i = 0; i < usize; i++)
			printf("%04x ", ubuff[i]);
		printf("\n");
		*/

		bi = ubrk_open(UBRK_CHARACTER, 0, ubuff, usize, &errcode);
		if (U_FAILURE(errcode)) {
			printf("Error from ubrk_open: %s\n", u_errorName(errcode));
			assert(0);
		}
		p = ubrk_first(bi);
	}

	lua_getglobal(L, "utf8");
	lua_getfield(L, -1, "grapheme_indices");
	lua_pushlstring(L, (const char*)Data, Size);
	int err = lua_pcall(L, 1, 1, 0);
	assert(!err);
	assert(lua_iscfunction(L, -1));
	lua_CFunction iterator = lua_tocfunction(L, -1);

	while (true) {
		lua_pushvalue(L, -1); // duplicate iterator (on top of stack)
		int err = lua_pcall(L, 0, 2, 0);
		if (err) {
			assert(!valid_utf8);
			break;
		}

		if (lua_isnil(L, -1)) {
			/* Finished iteration */
			if (valid_utf8) {
				p = ubrk_next(bi);
				assert(p == UBRK_DONE);
			}
			break;
		} else {
			assert(lua_isnumber(L, -1));
			assert(lua_isnumber(L, -2));
			int start = lua_tonumber(L, -2);
			int end = lua_tonumber(L, -1);
			lua_pop(L, 2);
			if (valid_utf8) {
				printf("start = %d, end = %d, p = %d\n", start, end, p);
				/* start and end are byte offsets, p is a codepoint offset */
				assert(p == utf16_code_unit_len(Data, start-1));
				p = ubrk_next(bi);
				printf("moved to next boundary, now p = %d\n", p);
				printf("utf16_code_unit_len(Data, end) = %zu\n", utf16_code_unit_len(Data, end));
				assert(p != UBRK_DONE);
				assert(p == utf16_code_unit_len(Data, end));
			}
		}
	}

	lua_settop(L, 0); // clear Lua stack

	free(ubuff);
	if (icu_converter)
		ucnv_close(icu_converter);
	if (bi)
		ubrk_close(bi);

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
