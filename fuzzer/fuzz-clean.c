#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	lua_getglobal(L, "utf8");
	lua_getfield(L, -1, "clean");

	const char *orig_data = (const char*)Data;

	uint8_t *Comma = memchr(Data, ',', Size);
	const char *repl = NULL;
	size_t repl_len;

	if (Comma) {
		/* We will pass two arguments (the 2nd one is optional) */
		lua_pushlstring(L, (const char*)Data, Comma - Data);
		Size -= Comma - Data + 1;
		Data = Comma + 1;
		repl = (const char*)Data;
		repl_len = Size;
	}

	lua_pushlstring(L, (const char*)Data, Size);

	size_t input_len = lua_objlen(L, Comma ? -2 : -1);

	/*
	const char *dbg = lua_tostring(L, Comma ? -2 : -1);
	printf("Input length = %zu\n", input_len);
	printf("Input = ");
	for (int i = 0; i < input_len; i++)
		printf("%02x", dbg[i] & 0xFF);
	printf("\n");
	*/

	int err = lua_pcall(L, Comma ? 2 : 1, 2, 0);
	/* printf("Err = %x\n", err); */

	if (err) {
		/* utf8.clean raised an error */
		assert(repl != NULL);

		/*
		if (err == 2) {
			const char *errmsg = lua_tostring(L, -1);
			printf("Err message = %s\n", errmsg);
		}

		printf("Replacement length = %zu\n", repl_len);
		printf("Replacement = ");
		for (int i = 0; i < repl_len; i++)
			printf("%02x", repl[i] & 0xFF);
		printf("\n");
		*/

		assert(!php_mbstring_check_utf8((unsigned char*)repl, repl_len));
	} else {
		assert(lua_isstring(L, -2));
		assert(lua_isboolean(L, -1));
		const char *str = lua_tostring(L, -2);
		int was_clean = lua_toboolean(L, -1);
		size_t output_len = lua_objlen(L, -2);

		/*
		printf("Output length = %zu\n", output_len);
		printf("Output = ");
		for (int i = 0; i < output_len; i++)
			printf("%02x", str[i] & 0xFF);
		printf("\n");
		*/

		if (was_clean) {
			assert(input_len == output_len);
			assert(memcmp(orig_data, str, input_len) == 0);
		} else {
			assert(input_len != output_len || memcmp(orig_data, str, input_len) != 0);
		}
		assert(php_mbstring_check_utf8((unsigned char*)str, output_len));
	}

	lua_settop(L, 0); // clear Lua stack

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
