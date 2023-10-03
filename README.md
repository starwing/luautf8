UTF-8 module for Lua 5.x
========================
[![Build Status](https://travis-ci.org/starwing/luautf8.svg?branch=master)](https://travis-ci.org/starwing/luautf8)
[![Coverage Status](https://coveralls.io/repos/github/starwing/luautf8/badge.svg?branch=master)](https://coveralls.io/github/starwing/luautf8?branch=master)

This module adds UTF-8 support to Lua.

It uses data extracted from
[Unicode Character Database](http://www.unicode.org/reports/tr44/),
and tested on Lua 5.2.3, Lua 5.3.0 and LuaJIT.

parseucd.lua is a pure Lua script which generates unidata.h, to support
converting characters and checking characters' category.

It is compatible with Lua's own string module and passes all
string and pattern matching tests in the Lua test suite[2].

It also adds some useful routines against UTF-8 features, such as:
- a convenient interface to escape Unicode sequences in strings.
- string insert/remove, since UTF-8 substring extraction may be expensive.
- calculate Unicode width, useful when implementing e.g. console emulator.
- a useful interface to translate Unicode offsets and byte offsets.
- checking UTF-8 strings for validity and removing invalid byte sequences.
- converting Unicode strings to normal form.

Note that to avoid conflict with Lua5.3's built-in library 'utf8',
this library produces a file like lua-utf8.dll or lua-utf8.so. so use
it like this:

```lua
local utf8 = require 'lua-utf8'
```

in your code :-(

[2]: http://www.lua.org/tests/5.2/


LuaRocks Installation
---------------------
`luarocks install luautf8`

It's now fully-compatible with Lua 5.3's utf8 library, so replacing this
file (and headers) with lutf8lib.c from the Lua 5.3 sources is also okay.

Usage
-----

Many routines are the same as Lua's string module:
- `utf8.byte`
- `utf8.char`
- `utf8.find`
- `utf8.gmatch`
- `utf8.gsub`
- `utf8.len`
- `utf8.lower`
- `utf8.match`
- `utf8.reverse`
- `utf8.sub`
- `utf8.upper`

The documentation of these functions can be found in the Lua manual[3].

[3]: http://www.lua.org/manual/5.2/manual.html#6.4


Some routines in string module needn't support Unicode:
- `string.dump`
- `string.format`
- `string.rep`

They are NOT in utf8 module.

Some routines are for compatibility with Lua 5.3's basic UTF-8 support library:
- `utf8.offset`
- `utf8.codepoint`
- `utf8.codes`

See Lua5.3's manual for usage.

Some routines are new, with some Unicode-spec functions:

### utf8.escape(str) -> utf8 string
escape a str to UTF-8 format string. It supports several escape formats:

 * `%ddd` - which ddd is a decimal number at any length:
   change Unicode code point to UTF-8 format.
 * `%{ddd}` - same as `%nnn` but has bracket around.
 * `%uddd` - same as `%ddd`, u stands Unicode
 * `%u{ddd}` - same as `%{ddd}`
 * `%xhhh` - hexadigit version of `%ddd`
 * `%x{hhh}` same as `%xhhh`.
 * `%?` - '?' stands for any other character: escape this character.

#### Examples:
```lua
local u = utf8.escape
print(u"%123%u123%{123}%u{123}%xABC%x{ABC}")
print(u"%%123%?%d%%u")
```


### utf8.charpos(s[[, charpos], index]) -> charpos, code point
convert UTF-8 position to byte offset.
if only `index` is given, return byte offset of this UTF-8 char index.
if both `charpos` and `index` is given, a new `charpos` will be
calculated, by adding/subtracting UTF-8 char `index` to current `charpos`.
in all cases, it returns a new char position, and code point (a
number) at this position.


### utf8.next(s[, charpos[, index]]) -> charpos, code point
iterate though the UTF-8 string s.
If only s is given, it can used as a iterator:
```lua
for pos, code in utf8.next, "utf8-string" do
   -- ...
end
```
if only s and `charpos` are given, return the byte offset of the next codepoint
in the string.
if `charpos` and `index` are given, a new `charpos` will be calculated, by
adding/subtracting UTF-8 char offset to current charpos.
in all cases, it returns a new char position (in bytes), and code point
(a number) at this position.


### utf8.insert(s[, idx], substring) -> new_string
insert a substring into s. If `idx` is given, insert the substring before
the char at this index; otherwise, substring will be concatenated onto s.
`idx` can be negative.


### utf8.remove(s[, start[, stop]]) -> new_string
delete a substring in s. If neither `start` nor `stop` is given, delete the
last UTF-8 char in s, otherwise delete chars from `start` to the end of s. if
`stop` is given, delete chars from `start` to `stop` (including `start` and `stop`).
`start` and `stop` can be negative.


### utf8.width(s[, ambi_is_double[, default_width]]) -> width
calculate the width of UTF-8 string s. if `ambi_is_double` is given,
characters with ambiguous width will be treated as having width 2.
Otherwise, they will be treated as having width 1.
the width of fullwidth/doublewidth characters is 2, and the width of other
characters is 1.
if `default_width` is given, it will be used as the width of unprintable
characters. (If you will replace unprintable characters with a placeholder,
pass its width as `default_width`.)
if s is a code point, return the width of this code point.


### utf8.widthindex(s, location[, ambi_is_double[, default_width]]) -> idx, offset, width
return the character index at given location in string s, where location is
in width units. this is the inverse operation of utf8.width().
if the requested location does not fall at a character boundary, `offset` will be
greater than 1; specifically, if the location is at the second column (middle)
of a wide char, `offset` will be 2. the width of the character at idx is returned also.


### utf8.title(s) -> new_string
### utf8.fold(s) -> new_string
converts UTF-8 string s to title-case, or folded case (used for
case-insensitive comparison).
if s is a number, it's treated as a code point and a converted code
point (number) is returned.
utf8.lower/utf8.upper has the same extension.


### utf8.ncasecmp(a, b) -> [-1,0,1]
compare a and b without case, -1 means a < b, 0 means a == b and 1 means a > b.


### utf8.isvalid(s) -> boolean
check whether s is a valid UTF-8 string or not.


### utf8.clean(s[, replacement_string]) -> cleaned_string, was_valid
replace any invalid UTF-8 byte sequences in s with the replacement string.
if no replacement string is provided, the default is "�" (REPLACEMENT CHARACTER U+FFFD).
note that *any* number of consecutive invalid bytes will be replaced by a single copy of the replacement string.
the 2nd return value is true if the original string was already valid (meaning no replacements were made).


### utf8.invalidoffset(s[, init]) -> offset
return the byte offset within s of the first invalid UTF-8 byte sequence.
(1 is the first byte of the string.)
if s is a valid UTF-8 string, return nil.
the optional numeric argument init specifies where to start the search; its default value is 1 and can be negative.


### utf8.isnfc(s) -> boolean
check whether s is in Normal Form C or not.
"Normal Form C" means that whenever possible, combining marks are combined with a preceding codepoint. For example, instead of U+0041 (LATIN CAPITAL LETTER A) U+00B4 (ACUTE ACCENT), an NFC string will use U+00C1 (LATIN CAPITAL LETTER A WITH ACUTE). Also, some deprecated codepoints are converted to the recommended replacements.
since the same sequence of characters can be represented in more than one way in Unicode, it is better to ensure strings are in Normal Form before comparing them.
an error may be raised if s is not a valid UTF-8 string.


### utf8.normalize_nfc(s) -> normal_string, was_nfc
convert s to Normal Form C.
the 2nd return value is true if the original string was already in NFC (meaning no modifications were made).
an error will be raised if s is not a valid UTF-8 string.


### utf8.grapheme_indices(s[, start[, stop]]) -> iterator
return an iterator which yields the starting and ending byte index of each successive grapheme cluster in s. This range of bytes is inclusive of the endpoints, so the yielded values can be passed to `string.sub` to extract the grapheme cluster.
if you provide `start` and `stop` byte indices, then the iterator will only cover the requested byte range. `start` and `stop` should fall on character boundaries, since an error will be raised if the requested byte range is not a valid UTF-8 string.
```lua
local i = 1
for from,to in utf8.grapheme_indices(s) do
  print("grapheme cluster "..i.." is from byte "..from.." to byte "..to)
  i = i + 1
end
```


Improvement needed
------------------

- add Lua 5.3 spec test-suite.
- more test case.
- grapheme-compose support, and affect in utf8.reverse and utf8.width


License
-------
It uses the same license as Lua: http://www.lua.org/license.html
