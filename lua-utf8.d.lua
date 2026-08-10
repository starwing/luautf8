--- @meta lua-utf8

-- Type definitions for luautf8 (https://github.com/starwing/luautf8).
-- API reference: README.md. Compatible with Lua 5.3 utf8 library.

local utf8 = {}

-- ================================ Constants ================================

--- Pattern matching the exact location of a UTF-8 byte sequence in a string.
utf8.charpattern = "[\0-\x7F\xC2-\xF4][\x80-\xBF]*"

-- ==================== Lua 5.3 utf8 compatibility ====================

--- Returns the position (in bytes) where the encoding of the n-th character
--- of s (counting from position 1) starts, or the position after the i-th
--- character. Returns nil if n is 0 or out of range.
--- @param s string
--- @param n integer
--- @param i? integer
--- @return integer?
function utf8.offset(s, n, i) end

--- Returns the code points of the substring starting at position i and ending
--- at j (both inclusive, default 1 and #s).
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return integer ...
function utf8.codepoint(s, i, j) end

--- Returns an iterator over the UTF-8 characters of s.
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return fun(): integer, integer
function utf8.codes(s, i, j) end

-- ==================== string module compatibility ====================

--- Returns the internal numeric codes of the characters of s.
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return integer ...
function utf8.byte(s, i, j) end

--- Returns a string with each argument converted to a UTF-8 byte sequence.
--- @param ... integer
--- @return string
function utf8.char(...) end

--- Finds the first occurrence of pattern in s. Returns nil if not found.
--- @param s string
--- @param pattern string
--- @param init? integer
--- @param plain? boolean
--- @return integer? start
--- @return integer? end
function utf8.find(s, pattern, init, plain) end

--- Returns an iterator over all non-overlapping matches of pattern in s.
--- @param s string
--- @param pattern string
--- @return fun(): string ...
function utf8.gmatch(s, pattern) end

--- Replaces every occurrence of pattern with repl, returning the new string
--- and the number of substitutions.
--- @param s string
--- @param pattern string
--- @param repl string|table|function
--- @param n? integer
--- @return string
--- @return integer
function utf8.gsub(s, pattern, repl, n) end

--- Returns the number of UTF-8 characters in s, or nil plus an error message
--- if s is not a valid UTF-8 string.
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return integer? len
--- @return string? err
function utf8.len(s, i, j) end

--- Converts s to lowercase. With an integer argument, converts a code point.
--- @overload fun(s: string): string
--- @overload fun(cp: integer): integer
--- @param s string|integer
--- @return string|integer
function utf8.lower(s) end

--- Matches pattern in s, returning the captures (or the whole match).
--- @param s string
--- @param pattern string
--- @param init? integer
--- @return string ...
function utf8.match(s, pattern, init) end

--- Returns the reverse of s. Reverses by character, not by byte.
--- @param s string
--- @return string
function utf8.reverse(s) end

--- Returns the substring of s starting at i and ending at j.
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return string
function utf8.sub(s, i, j) end

--- Converts s to uppercase. With an integer argument, converts a code point.
--- @overload fun(s: string): string
--- @overload fun(cp: integer): integer
--- @param s string|integer
--- @return string|integer
function utf8.upper(s) end

-- ======================== Unicode-specific ========================

--- Escapes s to UTF-8 format (supports %ddd, %{ddd}, %uddd, %u{ddd},
--- %xhhh, %x{hhh}, and %? for any other character).
--- @param s string
--- @return string
function utf8.escape(s) end

--- Converts UTF-8 character position n to byte position, also returning the
--- code point at the resulting position. Assumes s is valid UTF-8.
--- @param s string
--- @param n integer
--- @param i? integer
--- @return integer position
--- @return integer codepoint
function utf8.charpos(s, n, i) end

--- Iterates through s: returns the byte position of the next character after
--- i (or the n-th character), plus its code point. With only s given, usable
--- directly as an iterator.
--- @overload fun(s: string): fun(): integer?, integer?
--- @overload fun(s: string, i: integer, n?: integer): integer?, integer?
--- @return integer? position
--- @return integer? codepoint
function utf8.next(s, i, n) end

--- Inserts substring into s: before the n-th character (default: append).
--- @param s string
--- @param ... string|integer
--- @return string
function utf8.insert(s, ...) end

--- Deletes a substring from s: from i to j (inclusive), or the last character
--- when neither is given.
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return string
function utf8.remove(s, i, j) end

--- Calculates the display width of s (or of a substring) in columns, or of a
--- single code point when given a number.
--- @overload fun(s: string, i?: integer, j?: integer, ambiwidth?: 1|2, default_width?: integer): integer
--- @overload fun(cp: integer, ambiwidth?: 1|2, default_width?: integer): integer
--- @param s string|integer
--- @return integer
function utf8.width(s, i, j, ambiwidth, default_width) end

--- Returns the character index idx at display width in s, plus offset (which
--- column within idx-th character) and the character's width.
--- @param s string
--- @param width integer
--- @param i? integer
--- @param j? integer
--- @param ambiwidth? 1|2
--- @param default_width? integer
--- @return integer idx
--- @return integer offset
--- @return integer width
function utf8.widthindex(s, width, i, j, ambiwidth, default_width) end

--- Finds the byte position where truncation should occur to fit within a
--- display width limit (negative limit truncates from the back).
--- @param s string
--- @param limit integer
--- @param i? integer
--- @param j? integer
--- @param ambiwidth? 1|2
--- @param default_width? integer
--- @return integer position
--- @return integer remain
function utf8.widthlimit(s, limit, i, j, ambiwidth, default_width) end

--- Converts s to title-case. With an integer argument, converts a code point.
--- @overload fun(s: string): string
--- @overload fun(cp: integer): integer
--- @param s string|integer
--- @return string|integer
function utf8.title(s) end

--- Converts s to folded case (for case-insensitive comparison).
--- With an integer argument, converts a code point.
--- @overload fun(s: string): string
--- @overload fun(cp: integer): integer
--- @param s string|integer
--- @return string|integer
function utf8.fold(s) end

--- Compares a and b without case: -1 if a < b, 0 if equal, 1 if a > b.
--- @param a string
--- @param b string
--- @return -1|0|1
function utf8.ncasecmp(a, b) end

--- Returns true if s is a valid UTF-8 string.
--- @param s string
--- @return boolean
function utf8.isvalid(s) end

--- Replaces invalid UTF-8 byte sequences in s with replacement (default: U+FFFD).
--- @param s string
--- @param replacement? string
--- @return string result
--- @return boolean was_valid
function utf8.clean(s, replacement) end

--- Returns the byte position of the first invalid byte sequence, or nil.
--- @param s string
--- @param i? integer
--- @return integer?
function utf8.invalidoffset(s, i) end

--- Returns true if s is in Normal Form C. Raises an error for invalid UTF-8.
--- @param s string
--- @return boolean
function utf8.isnfc(s) end

--- Converts s to Normal Form C.
--- @param s string
--- @return string result
--- @return boolean was_nfc
function utf8.normalize_nfc(s) end

--- Returns an iterator over grapheme clusters of s, yielding the inclusive
--- byte range [from, to] of each cluster.
--- @param s string
--- @param i? integer
--- @param j? integer
--- @return fun(): integer, integer
function utf8.grapheme_indices(s, i, j) end

return utf8
