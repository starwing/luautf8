#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <math.h>

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
	lua_getfield(L, -1, "invalidoffset");

	int offset = 0;
	if (Size > 2) {
		offset = *Data++;
		if (*Data++ % 2 == 1)
			offset = -offset;
		Size -= 2;
	}

	lua_pushlstring(L, (const char*)Data, Size);
	lua_pushinteger(L, offset);

	/*
	const char *dbg = lua_tostring(L, -2);
	printf("Input length = %zu\n", Size);
	printf("Input = ");
	for (int i = 0; i < Size; i++)
		printf("%02x", Data[i] & 0xFF);
	printf("\n");
	printf("Offset = %d\n", offset);
	*/

	lua_call(L, 2, 1);

	assert(lua_isnumber(L, -1) || lua_isnil(L, -1));

	/* Convert offset into a positive number from 1 - length of string
	 * (offset is 1-based, not 0-based) */
	if (offset < 0) {
		offset = Size + offset + 1;
		if (offset <= 0) {
			offset = 1;
		}
	} else if (offset == 0) {
		offset = 1;
	} else if (offset > Size) {
		offset = Size + 1;
	}

	if (lua_isnumber(L, -1)) {
		double retval = lua_tonumber(L, -1);
		/* printf("Retval = %d\n", (int)retval); */
		assert(floor(retval) == ceil(retval)); /* Although 'double', it's actually an integer */
		assert(retval >= offset);
		assert(retval > 0);
		assert(retval <= Size);
		assert(!php_mbstring_check_utf8((unsigned char*)Data + (int)retval - 1, Size - (int)retval + 1));
	} else {
		assert(php_mbstring_check_utf8((unsigned char*)Data + offset - 1, Size - offset + 1));
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
