/*
  Basic UTF-8 manipulation routines
  by Jeff Bezanson
  placed in the public domain Fall 2005

  This code is designed to provide the utilities you need to manipulate
  UTF-8 as an internal string encoding. These functions do not perform the
  error checking normally needed when handling UTF-8 data, so if you happen
  to be from the Unicode Consortium you will want to flay me alive.
  I do this because error checking can be performed at the boundaries (I/O),
  with these routines reserved for higher performance on data known to be
  valid.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#ifdef WIN32
#include <windows.h>
#else
#include <alloca.h>
#endif

#include "utf8conv.h"

static WCHAR *utf8ToUnicode(const char *zFilename){
	int nChar;
	WCHAR *zWideFilename;

	nChar = MultiByteToWideChar(CP_UTF8, 0, zFilename, -1, NULL, 0);
	zWideFilename = malloc(nChar*sizeof(zWideFilename[0]));
	if (zWideFilename == 0){
		return 0;
	}
	nChar = MultiByteToWideChar(CP_UTF8, 0, zFilename, -1, zWideFilename, nChar);
	if (nChar == 0){
		free(zWideFilename);
		zWideFilename = 0;
	}
	return zWideFilename;
}

/*
** Convert microsoft unicode to UTF-8.  Space to hold the returned string is
** obtained from malloc().
*/
static char *unicodeToUtf8(const WCHAR *zWideFilename){
	int nByte;
	char *zFilename;

	nByte = WideCharToMultiByte(CP_UTF8, 0, zWideFilename, -1, 0, 0, 0, 0);
	zFilename = malloc(nByte);
	if (zFilename == 0){
		return 0;
	}
	nByte = WideCharToMultiByte(CP_UTF8, 0, zWideFilename, -1, zFilename, nByte,
		0, 0);
	if (nByte == 0){
		free(zFilename);
		zFilename = 0;
	}
	return zFilename;
}

/*
** Convert an ansi string to microsoft unicode, based on the
** current codepage settings for file apis.
**
** Space to hold the returned string is obtained
** from malloc.
*/
static WCHAR *mbcsToUnicode(const char *zFilename){
	int nByte;
	WCHAR *zMbcsFilename;
	int codepage = AreFileApisANSI() ? CP_ACP : CP_OEMCP;

	nByte = MultiByteToWideChar(codepage, 0, zFilename, -1, NULL, 0)*sizeof(WCHAR);
	zMbcsFilename = malloc(nByte*sizeof(zMbcsFilename[0]));
	if (zMbcsFilename == 0){
		return 0;
	}
	nByte = MultiByteToWideChar(codepage, 0, zFilename, -1, zMbcsFilename, nByte);
	if (nByte == 0){
		free(zMbcsFilename);
		zMbcsFilename = 0;
	}
	return zMbcsFilename;
}

/*
** Convert microsoft unicode to multibyte character string, based on the
** user's Ansi codepage.
**
** Space to hold the returned string is obtained from
** malloc().
*/
static char *unicodeToMbcs(const WCHAR *zWideFilename){
	int nByte;
	char *zFilename;
	int codepage = AreFileApisANSI() ? CP_ACP : CP_OEMCP;

	nByte = WideCharToMultiByte(codepage, 0, zWideFilename, -1, 0, 0, 0, 0);
	zFilename = malloc(nByte);
	if (zFilename == 0){
		return 0;
	}
	nByte = WideCharToMultiByte(codepage, 0, zWideFilename, -1, zFilename, nByte,
		0, 0);
	if (nByte == 0){
		free(zFilename);
		zFilename = 0;
	}
	return zFilename;
}

/*
** Convert multibyte character string to UTF-8.  Space to hold the
** returned string is obtained from malloc().
*/
char *sqlite3_win32_mbcs_to_utf8(const char *zFilename){
	char *zFilenameUtf8;
	WCHAR *zTmpWide;

	zTmpWide = mbcsToUnicode(zFilename);
	if (zTmpWide == 0){
		return 0;
	}
	zFilenameUtf8 = unicodeToUtf8(zTmpWide);
	free(zTmpWide);
	return zFilenameUtf8;
}

/*
** Convert UTF-8 to multibyte character string.  Space to hold the
** returned string is obtained from malloc().
*/
char *sqlite3_win32_utf8_to_mbcs(const char *zFilename){
	char *zFilenameMbcs;
	WCHAR *zTmpWide;

	zTmpWide = utf8ToUnicode(zFilename);
	if (zTmpWide == 0){
		return 0;
	}
	zFilenameMbcs = unicodeToMbcs(zTmpWide);
	free(zTmpWide);
	return zFilenameMbcs;
}
