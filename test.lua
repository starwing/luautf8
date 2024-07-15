local utf8 = require 'lua-utf8'
local unpack = unpack or table.unpack
local E = utf8.escape

local function get_codes(s)
   return table.concat({utf8.byte(s, 1, -1)}, ' ')
end

local t = { 20985, 20984, 26364, 25171, 23567, 24618, 20861 } 
-- test escape & len
assert(get_codes(E"%123%xabc%x{ABC}%d%u{456}") == '123 2748 2748 100 456')

local s = E('%'..table.concat(t, '%'))
assert(utf8.len(s) == 7)
assert(get_codes(s) == table.concat(t, ' '))


-- test offset

local function assert_error(f, msg)
   local s,e = pcall(f)
   return assert(not s and e:match(msg))
end

assert(utf8.offset("中国", 0) == 1)
assert(utf8.offset("中国", 0,1) == 1)
assert(utf8.offset("中国", 0,2) == 1)
assert(utf8.offset("中国", 0,3) == 1)
assert(utf8.offset("中国", 0,4) == 4)
assert(utf8.offset("中国", 0,5) == 4)
assert(utf8.offset("中国", 1) == 1)
assert_error(function() utf8.offset("中国", 1,2) end,
             "initial position is a continuation byte")
assert(utf8.offset("中国", 2) == 4)
assert(utf8.offset("中国", 3) == 7)
assert(utf8.offset("中国", 4) == nil)
assert(utf8.offset("中国", -1,-3) == 1)
assert(utf8.offset("中国", -1,1) == nil)

-- test byte
local function assert_table_equal(t1, t2, i, j)
   i = i or 1
   j = j or #t2
   local len = j-i+1
   assert(#t1 == len)
   for cur = 1, len do
      assert(t1[cur] == t2[cur+i-1])
   end
end
assert_table_equal({utf8.byte(s, 2)}, t, 2, 2)
assert_table_equal({utf8.byte(s, 1, -1)}, t)
assert_table_equal({utf8.byte(s, -100)}, {})
assert_table_equal({utf8.byte(s, -100, -200)}, {})
assert_table_equal({utf8.byte(s, -200, -100)}, {})
assert_table_equal({utf8.byte(s, 100)}, {})
assert_table_equal({utf8.byte(s, 100, 200)}, {})
assert_table_equal({utf8.byte(s, 200, 100)}, {})


-- test char
assert(s == utf8.char(unpack(t)))

-- test range
for i = 1, #t do
    assert(utf8.byte(s, i) == t[i])
end

-- test sub
assert(get_codes(utf8.sub(s, 2, -2)) == table.concat(t, ' ', 2, #t-1))
assert(get_codes(utf8.sub(s, -100)) == table.concat(t, ' '))
assert(get_codes(utf8.sub(s, -100, -200)) == "")
assert(get_codes(utf8.sub(s, -100, -100)) == "")
assert(get_codes(utf8.sub(s, -100, 0)) == "")
assert(get_codes(utf8.sub(s, -200, -100)) == "")
assert(get_codes(utf8.sub(s, 100, 200)) == "")
assert(get_codes(utf8.sub(s, 200, 100)) == "")


-- test insert/remove
assert(utf8.insert("abcdef", "...") == "abcdef...")
assert(utf8.insert("abcdef", 0, "...") == "abcdef...")
assert(utf8.insert("abcdef", 1, "...") == "...abcdef")
assert(utf8.insert("abcdef", 6, "...") == "abcde...f")
assert(utf8.insert("abcdef", 7, "...") == "abcdef...")
assert(utf8.insert("abcdef", 3, "...") == "ab...cdef")
assert(utf8.insert("abcdef", -3, "...") == "abc...def")
assert(utf8.remove("abcdef", 3, 3) == "abdef")
assert(utf8.remove("abcdef", 3, 4) == "abef")
assert(utf8.remove("abcdef", 4, 3) == "abcdef")
assert(utf8.remove("abcdef", -3, -3) == "abcef")
assert(utf8.remove("abcdef", 100) == "abcdef")
assert(utf8.remove("abcdef", -100) == "")
assert(utf8.remove("abcdef", -100, 0) == "abcdef")
assert(utf8.remove("abcdef", -100, -200) == "abcdef")
assert(utf8.remove("abcdef", -200, -100) == "abcdef")
assert(utf8.remove("abcdef", 100, 200) == "abcdef")
assert(utf8.remove("abcdef", 200, 100) == "abcdef")

do
    local s = E"a%255bc"
    assert(utf8.len(s, 4))
    assert(string.len(s, 6))
    assert(utf8.charpos(s) == 1)
    assert(utf8.charpos(s, 0) == 1)
    assert(utf8.charpos(s, 1) == 1)
    assert(utf8.charpos(s, 2) == 2)
    assert(utf8.charpos(s, 3) == 4)
    assert(utf8.charpos(s, 4) == 5)
    assert(utf8.charpos(s, 5) == nil)
    assert(utf8.charpos(s, 6) == nil)
    assert(utf8.charpos(s, -1) == 5)
    assert(utf8.charpos(s, -2) == 4)
    assert(utf8.charpos(s, -3) == 2)
    assert(utf8.charpos(s, -4) == 1)
    assert(utf8.charpos(s, -5) == nil)
    assert(utf8.charpos(s, -6) == nil)
    assert(utf8.charpos(s, 3, -1) == 2)
    assert(utf8.charpos(s, 3, 0) == 2)
    assert(utf8.charpos(s, 3, 1) == 4)
    assert(utf8.charpos(s, 6, -3) == 2)
    assert(utf8.charpos(s, 6, -4) == 1)
    assert(utf8.charpos(s, 6, -5) == nil)
end

local idx = 1
for pos, code in utf8.next, s do
   assert(t[idx] == code)
   idx = idx + 1
end

assert(utf8.ncasecmp("abc", "AbC") == 0)
assert(utf8.ncasecmp("abc", "AbE") == -1)
assert(utf8.ncasecmp("abe", "AbC") == 1)
assert(utf8.ncasecmp("abc", "abcdef") == -1)
assert(utf8.ncasecmp("abcdef", "abc") == 1)
assert(utf8.ncasecmp("abZdef", "abcZef") == 1)

assert(utf8.gsub("x^[]+$", "%p", "%%%0") == "x%^%[%]%+%$")


-- test invalid

-- 1110-1010 10-000000 0110-0001
do
   local s = "\234\128\97"
   assert(utf8.len(s, nil, nil, true) == 2)
   assert_table_equal({utf8.len(s)}, {nil, 1}, 1, 2)

   -- 1111-0000 10-000000 10-000000 ...
   s = "\240\128\128\128\128"
   assert_table_equal({utf8.len(s)}, {nil, 1}, 1, 2)
end


-- test compose
local function assert_fail(f, patt)
   local ok, msg = pcall(f)
   assert(not ok)
   assert(msg:match(patt), msg)
end
do
   local s = "नमस्ते"
   assert(utf8.len(s) == 6)
   assert(utf8.reverse(s) == "तेस्मन")
   assert(utf8.reverse(s.." ", true) == " ेत्समन")
   assert(utf8.match(s..'\2', "%g+") == s)
   assert_fail(function() utf8.reverse(E"%xD800") end, "invalid UTF%-8 code")
end


-- test match
assert(utf8.match('%c', '') == nil) -- %c does not match U+F000


-- test codepoint
for i = 1, 1000 do
   assert(utf8.codepoint(E("%"..i)) == i)
end
assert_fail(function() utf8.codepoint(E"%xD800") end, "invalid UTF%-8 code")

-- test escape
assert_fail(function() E"%{1a1}" end, "invalid escape 'a'")


-- test codes
local result = { [1]  = 20985; [4]  = 20984; [7]  = 26364;
   [10] = 25171; [13] = 23567; [16] = 24618; [19] = 20861; }
for p, c in utf8.codes(s) do
   assert(result[p] == c)
end
for p, c in utf8.codes(s, true) do
   assert(result[p] == c)
end
assert_fail(function()
   for p, c in utf8.codes(E"%xD800") do
      assert(result[p] == c)
   end
end, "invalid UTF%-8 code")


-- test width
assert(utf8.width('नमस्ते\2') == 5)
assert(utf8.width(E'%xA1') == 1)
assert(utf8.width(E'%xA1', 2) == 2)
assert(utf8.width(E'%x61C') == 0)
assert(utf8.width "A" == 1)
assert(utf8.width "Ａ" == 2)
assert(utf8.width(97) == 1)
assert(utf8.width(65313) == 2)
assert_fail(function() utf8.width(true) end, "number/string expected, got boolean")
assert(utf8.widthindex("abcdef", 3) == 3)
assert(utf8.widthindex("abcdef", 7) == 7)

-- test patterns
assert_fail(function() utf8.gsub("a", ".", function() return {} end) end,
   "invalid replacement value %(a table%)")
assert_fail(function() utf8.gsub("a", ".", "%z") end,
   "invalid use of '%%' in replacement string")
assert(utf8.find("abcabc", "ab", -10) == 1)

-- test charpattern
do
  local subj, n = "school=школа", 0
  for c in string.gmatch(subj, utf8.charpattern) do n = n+1 end
  assert(n == utf8.len(subj))
end


-- test isvalid
local good_strings = {
   '',
   'A',
   'abcdefghijklmnopqrstuvwxyz',
   "``",
   "@",
   'नमस्ते',
   '中国',
   '日本語０１２３４５６７８９０。',
   'ひらがな',
   'Καλημέρα',
   'АБВГ',
   '⡌⠁⠧⠑ ⠼',
   '∑ f(i)',
   'Οὐχὶ ταὐτὰ παρίσταταί μοι γιγνώσκειν, ὦ ἄνδρες ᾿Αθηναῖοι, ὅταν τ᾿ εἰς τὰ πράγματα ἀποβλέψω καὶ ὅταν πρὸς τοὺς',
   'ABCDEFGHIJKLMNOPQRSTUVWXYZ /0123456789 abcdefghijklmnopqrstuvwxyz £©µÀÆÖÞßéöÿАБВГДабвгд∀∂∈ℝ∧∪≡∞ ↑↗↨↻⇣',
   'გთხოვთ ახლავე გაიაროთ რეგისტრაცია Unicode-ის მეათე საერთაშორისო კონფერენციაზე დასასწრებად, რომელიც გაიმართება 10-12 მარტს',
   '\000' -- NUL is valid in UTF-8
}

for _, good in ipairs(good_strings) do
   assert(utf8.isvalid(good))
end

assert(not utf8.isvalid("\255")) -- illegal byte 0xFF
assert(not utf8.isvalid("abc\254def")) -- illegal byte 0xFE

assert(not utf8.isvalid("123 \223")) -- truncated code unit 0xDF
assert(not utf8.isvalid("123 \239\191")) -- truncated code unit 0xEF BF
assert(not utf8.isvalid("123 \240\191")) -- truncated code unit 0xF0 BF
assert(not utf8.isvalid("123 \240\191\191")) -- truncated code unit 0xF0 BF BF

assert(not utf8.isvalid('\223ABC')) -- code unit 0xDF ended too soon and went to ASCII
assert(not utf8.isvalid('\239\191ABC')) -- code unit 0xEF BF ended too soon and went to ASCII
assert(not utf8.isvalid('\240\191ABC')) -- code unit 0xF0 BF ended too soon and went to ASCII
assert(not utf8.isvalid('\240\191\191ABC')) -- code unit 0xF0 BF BF ended too soon and went to ASCII

assert(not utf8.isvalid('\223中')) -- code unit 0xDF ended too soon and went to another multi-byte char
assert(not utf8.isvalid('\239\191中')) -- code unit 0xEF BF ended too soon and went to another multi-byte char
assert(not utf8.isvalid('\240\191中')) -- code unit 0xF0 BF ended too soon and went to another multi-byte char
assert(not utf8.isvalid('\240\191\191中')) -- code unit 0xF0 BF BF ended too soon and went to another multi-byte char

assert(utf8.isvalid('\237\159\191')) -- U+D7FF is valid
assert(not utf8.isvalid('\237\160\128')) -- U+D800; reserved for UTF-16 surrogate
assert(not utf8.isvalid('\237\175\191')) -- U+DBFF; reserved for UTF-16 surrogate
assert(not utf8.isvalid('\237\191\191')) -- U+DFFF; reserved for UTF-16 surrogate
assert(utf8.isvalid('\238\128\128')) -- U+E000 is valid

assert(utf8.isvalid('\244\143\191\191')) -- U+10FFFF is valid
assert(not utf8.isvalid('\244\144\128\128')) -- U+110000 is not valid
assert(not utf8.isvalid('\247\191\191\191')) -- U+1FFFFF is not valid

assert(not utf8.isvalid('\128')) -- continuation byte outside a multi-byte char
assert(not utf8.isvalid('A\128A')) -- continuation byte outside a multi-byte char
assert(not utf8.isvalid('中\128')) -- continuation byte outside a multi-byte char

assert(not utf8.isvalid('\193\191')) -- overlong code unit
assert(not utf8.isvalid('\224\159\191')) -- overlong code unit
assert(not utf8.isvalid('\240\143\191\191')) -- overlong code unit

-- test clean
local cleaned, was_clean

for _, good in ipairs(good_strings) do
   cleaned, was_clean = utf8.clean(good)
   assert(cleaned == good)
   assert(was_clean)
end

cleaned, was_clean = utf8.clean('A\128A')
assert(cleaned == 'A�A')
assert(not was_clean)

cleaned, was_clean = utf8.clean('\128')
assert(cleaned == '�')
assert(not was_clean)

cleaned, was_clean = utf8.clean('1\193\1912\224\159\1913\240\143\191\191', '???')
assert(cleaned == '1???2???3???')
assert(not was_clean)

cleaned, was_clean = utf8.clean('\237\160\128\237\175\191\237\191\191')
assert(cleaned == '�') -- an entire sequence of bad bytes just gets replaced with one replacement char
assert(not was_clean)

cleaned, was_clean = utf8.clean('123 \223', '')
assert(cleaned == '123 ')
assert(not was_clean)

cleaned, was_clean = utf8.clean('\239\191中', '')
assert(cleaned == '中')
assert(not was_clean)

assert_error(function() utf8.clean('abc', '\255') end, "replacement string must be valid UTF%-8")


-- test invalidoffset
for _, good in ipairs(good_strings) do
   assert(utf8.invalidoffset(good) == nil)
end

assert(utf8.invalidoffset("\255") == 1)
assert(utf8.invalidoffset("\255", 0) == 1)
assert(utf8.invalidoffset("\255", 1) == 1)
assert(utf8.invalidoffset("\255", 2) == nil)
assert(utf8.invalidoffset("\255", -1) == 1)
assert(utf8.invalidoffset("\255", -2) == 1)
assert(utf8.invalidoffset("\255", -3) == 1)

assert(utf8.invalidoffset("abc\254def") == 4)
assert(utf8.invalidoffset("abc\254def", 0) == 4)
assert(utf8.invalidoffset("abc\254def", 1) == 4)
assert(utf8.invalidoffset("abc\254def", 2) == 4)
assert(utf8.invalidoffset("abc\254def", 3) == 4)
assert(utf8.invalidoffset("abc\254def", 4) == 4)
assert(utf8.invalidoffset("abc\254def", 5) == nil)
assert(utf8.invalidoffset("abc\254def", 6) == nil)
assert(utf8.invalidoffset("abc\254def", -1) == nil)
assert(utf8.invalidoffset("abc\254def", -2) == nil)
assert(utf8.invalidoffset("abc\254def", -3) == nil)
assert(utf8.invalidoffset("abc\254def", -4) == 4)
assert(utf8.invalidoffset("abc\254def", -5) == 4)

assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 0) == 1)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 1) == 1)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 2) == 2)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 3) == 3)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 4) == 4)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 5) == 5)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', 6) == 6)
assert(utf8.invalidoffset('\237\160\128\237\175\191\237\191\191', -1) == 9)


local function parse_codepoints(s)
   local list = {}
   for hex in s:gmatch("%w+") do
      list[#list+1] = tonumber(hex, 16)
   end
   return utf8.char(unpack(list))
end

-- This is an official set of test cases for Unicode normalization
-- Provided by the Unicode Consortium
local normalization_test_cases = {}
local f = io.open('NormalizationTest.txt', 'r')
for line in f:lines() do
   if not line:match("^#") and not line:match("^@") then
      local src, nfc, nfd = line:match "([%w%s]+);([%w%s]+);([%w%s]+)"
      table.insert(normalization_test_cases, { src = parse_codepoints(src), nfc = parse_codepoints(nfc), nfd = parse_codepoints(nfd) })
   end
end


-- test isnfc
for _,case in ipairs(normalization_test_cases) do
   assert(utf8.isnfc(case.nfc))
   if case.src ~= case.nfc then
      assert(not utf8.isnfc(case.src))
   end
   if case.nfd ~= case.nfc and case.nfd ~= case.src then
      assert(not utf8.isnfc(case.nfd))
   end
end

-- Regression tests:
-- Although U+1100-115F are all leading Jamo (Korean characters), for some reason,
-- the normalization algorithm only combines U+1100-1112 with a following vowel Jamo
assert(utf8.isnfc("\225\133\133\225\133\163"))
-- In certain cases, we did not properly check if a combining mark was blocked from
-- combining with the preceding starter codepoint (by another combining mark with
-- the same canonicalization class)
assert(utf8.isnfc("\196\148\204\162\204\167"))
-- It is possible that a codepoint which is composed from a starter and combining mark
-- might be decomposed, then the resulting starter might be decomposed AGAIN, then
-- those two resulting combining marks might be reordered with a following combining
-- mark
assert(not utf8.isnfc("\199\154\204\164"))

-- test normalize_nfc
for _,case in ipairs(normalization_test_cases) do
   assert(utf8.normalize_nfc(case.src) == case.nfc)
   assert(utf8.normalize_nfc(case.nfc) == case.nfc)
   assert(utf8.normalize_nfc(case.nfd) == case.nfc)
end

-- Regression tests:
-- Long series of combining marks; these need to be sorted in canonical order
assert(utf8.normalize_nfc("\215\129\215\133\215\133\215\129\215\129\215\129\215\129\215\129\215\129") == "\215\129\215\129\215\129\215\129\215\129\215\129\215\129\215\133\215\133")
-- After converting combining marks to standard codepoints, it is possible their canonicalization class may change
-- If so, make sure they are still put in the correct order
assert(utf8.normalize_nfc("\200\135\204\163\204\169") == "\225\186\185\204\169\204\145")
-- This test case caused an out-of-bounds read where my code tried to sort an empty array
assert(utf8.normalize_nfc("\225\190\129\204\129") == "\225\190\133")
-- After converting one codepoint to two, as required by the NFC normalization tables,
-- if the 2nd resulting codepoint is a combining mark, we have to be ready to re-order
-- it with any following combining marks
assert(utf8.normalize_nfc("\224\165\152\204\184") == "\224\164\149\204\184\224\164\188")
-- It can also happen that a codepoint converts to a starter followed by TWO combining marks,
-- and we must be able to reorder BOTH of those combining marks with a following combining mark
assert(utf8.normalize_nfc("\239\172\172\204\184") == "\215\169\204\184\214\188\215\129")
-- It can even happen that a deprecated 'starter' codepoint (canonicalization class = 0)
-- can convert to 'combining mark' codepoints (canonicalization class != 0)
assert(utf8.normalize_nfc("\223\179\224\189\179") == "\224\189\177\224\189\178\223\179")
-- In certain cases, we did not properly check if a combining mark was blocked from
-- combining with the preceding starter codepoint (by another combining mark with
-- the same canonicalization class)
assert(utf8.normalize_nfc("\196\148\204\162\204\167") == "\196\148\204\162\204\167")
assert(utf8.normalize_nfc("\200\148\204\160\204\148\204\164") == "\200\148\204\160\204\164\204\148")
-- It is possible that a codepoint which is composed from a starter and combining mark
-- might be decomposed, then the resulting starter might be decomposed AGAIN, then
-- those two resulting combining marks might be reordered with a following combining
-- mark
assert(utf8.normalize_nfc("\199\154\204\164") == "\225\185\179\204\136\204\140")
-- When a codepoint decomposes to a starter followed by 2 combining marks, we need to
-- make sure those combining marks are in the right order with any following ones
assert(utf8.normalize_nfc("\199\160\205\129\204\168") == "\196\132\204\135\204\132\204\129")
-- Fixing another issue with ordering of combining marks after a codepoint decomposes
-- to a starter followed by 1 or 2 combining marks:
assert(utf8.normalize_nfc("\199\155\204\155\204\131\204\155") == "\198\175\204\155\204\136\204\128\204\131")


-- Official set of test cases for grapheme cluster segmentation, provided by Unicode Consortium
local grapheme_test_cases = {}
f = io.open('GraphemeBreakTest.txt', 'r')
for line in f:lines() do
   if not line:match("^#") and not line:match("^@") then
      line = line:gsub("#.*", "")
      line = line:gsub("^%s*÷%s*", "")
      line = line:gsub("%s*÷%s*$", "")
      local clusters = { "" }
      for str in line:gmatch("%S+") do
         if str == '×' then
            -- do nothing
         elseif str == '÷' then
            table.insert(clusters, "") -- start a new cluster
         else
            clusters[#clusters] = clusters[#clusters]..utf8.char(tonumber(str, 16))
         end
      end
      table.insert(grapheme_test_cases, { str=table.concat(clusters), clusters=clusters })
   end
end


-- test grapheme_indices
for _,case in ipairs(grapheme_test_cases) do
   local actual_clusters = {}
   for start,stop in utf8.grapheme_indices(case.str) do
      table.insert(actual_clusters, case.str:sub(start, stop))
   end
   assert(#actual_clusters == #case.clusters)
   for i,cluster in ipairs(case.clusters) do
      assert(actual_clusters[i] == cluster)
   end
end

-- try iterating over grapheme clusters in a substring
local clusters = {}
for a,b in utf8.grapheme_indices('ひらがな', 4, 9) do
   table.insert(clusters, a)
   table.insert(clusters, b)
end
for idx,value in ipairs({ 4, 6, 7, 9 }) do
   assert(clusters[idx] == value)
end

-- try private use codepoint followed by a combining character
clusters = {}
for a,b in utf8.grapheme_indices('\239\128\128\204\154') do
   table.insert(clusters, a)
   table.insert(clusters, b)
end
for idx,value in ipairs({ 1, 5 }) do
   assert(clusters[idx] == value)
end


print "OK"

-- cc: run='lua -- $input'

