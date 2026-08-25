cl /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE ^
    /MT /GS- /GL /Gy /Oy- /O2 /Oi /DNDEBUG ^
		/I C:\Devel\Lua54\include /DLUA_BUILD_AS_DLL C:\Devel\Lua54\lib\lua54.lib ^
		/LD lutf8lib.c ^
		/Felua-utf8.dll

