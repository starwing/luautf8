-- generate useful data from Unicode Character Database.
-- you should have these files in UCD folder in current path:
--   - UCD\CaseFolding.txt
--   - UCD\DerivedCoreProperties.txt
--   - UCD\DerivedNormalizationProps.txt
--   - UCD\EastAsianWidth.txt
--   - UCD\emoji\emoji-data.txt
--   - UCD\HangulSyllableType.txt
--   - UCD\IndicSyllabicCategory.txt
--   - UCD\PropList.txt
--   - UCD\UnicodeData.txt
--
--  files can be downloaded at: http://unicode.org/Public/UCD/latest/UCD/


local function parse_UnicodeData()
    -- UnicodeData.txt structions:
    -- 0. codepoint
    -- 1. name
    -- 2. general category
    -- 3. canonical combining class
    -- 4. bidi class
    -- 5. decomposition type/mapping
    -- 6. numeric type/value
    -- 7. numeric type/value
    -- 8. numeric type/value
    -- 9. bidi mirrored [YN]
    -- 10. old unicode name
    -- 11. iso comment
    -- 12. uppercase mapping
    -- 13. lowercase mapping
    -- 14. titlecase mapping
    local ucd = {}

    local patt = "^(%x+)"..(";([^;]-)"):rep(14).."$"

    local last_data

    for line in io.lines() do
        local cp, name, gc, canon_cls, bidi_class, decomposition, _,_,_, _, _,_, um, lm, tm = line:match(patt)
        assert(cp, line)
        cp = tonumber(cp, 16)
        lm = lm ~= "" and tonumber(lm, 16)
        um = um ~= "" and tonumber(um, 16)
        tm = tm ~= "" and tonumber(tm, 16)
        local decomp1, decomp2 = decomposition:match "^(%x+) (%x+)$"
        if decomp1 and decomp2 then
            decomposition = { tonumber(decomp1, 16), tonumber(decomp2, 16) }
        elseif decomposition:match("^%x+$") then
            decomposition = { tonumber(decomposition, 16) }
        else
            decomposition = nil
        end
        if last_data and last_data.name:match"First%>$" then
            assert(name:match"Last%>$", line)
            for i = last_data.cp, cp-1 do
                ucd[#ucd+1] = {
                    cp = i,
                    name = name,
                    gc = gc,
                    bidi_class = bidi_class,
                    lm = lm, um = um, tm = tm,
                    canon_cls = tonumber(canon_cls),
                    decomposition = decomposition
                }
            end
        end
        local data = {
            cp = cp,
            name = name,
            gc = gc,
            bidi_class = bidi_class,
            lm = lm, um = um, tm = tm,
            canon_cls = tonumber(canon_cls),
            decomposition = decomposition
        }
        ucd[#ucd+1] = data
        last_data = data
    end
    table.sort(ucd, function(a, b) return a.cp < b.cp end)

    return ucd
end

local function parse_EastAsianWidth()
    local wide, ambi = {}, {}

    for line in io.lines() do
        line = line:gsub("%s*%#.*$", "")
        if line ~= "" then
            local first, last, mark
            first, mark = line:match "^(%x+)%s*%;%s*(%w+)$"
            if first then
                last = first
            else
                first, last, mark = line:match "^(%x+)%.%.(%x+)%s*%;%s*(%w+)$"
                assert(first, line)
            end

            first = tonumber(first, 16)
            last = tonumber(last, 16)

            if mark == 'W' or mark == 'F' then
                for i = first, last do
                    wide[#wide+1] = i
                end
            elseif mark == 'A' then
                for i = first, last do
                    ambi[#ambi+1] = i
                end
            end
        end
    end

    return wide, ambi
end

local function parse_CaseFolding()
    local mapping = {}
    for line in io.lines() do
        line = line:gsub("%s*%#.*$", "")
        if line ~= "" then
            local cp, class, mcp = line:match "^%s*(%x+)%s*;%s*(%w+)%s*;%s*(%x+)"
            assert(cp, line)
            if class == 'C' or class == 'S' then
                cp = tonumber(cp, 16)
                mcp = tonumber(mcp, 16)
                mapping[#mapping+1] = { cp = cp, mapping = mcp }
            end
        end
    end
    return mapping
end

local function parse_PropList(f)
    local ranges = {}
    local lookup = {}

    local arg = f
    if type(f) == 'table' then
        f = function(cp) return arg[cp] end
    elseif type(f) == 'string' then
        f = function(cp) return arg == cp end
    end

    for line in io.lines() do
        line = line:gsub("%s*%#.*$", "")
        if line ~= "" then
            local first, last, mark
            first, mark = line:match "^(%x+)%s*%;%s*([%w%s_;]+)%s*$"
            if first then
                last = first
            else
                first, last, mark = line:match "^(%x+)%.%.(%x+)%s*%;%s*([%w%s_;]+)%s*$"
                assert(first, line)
            end

            first = tonumber(first, 16)
            last = tonumber(last, 16)

            if f(mark) then
                for i = first, last do
                    if not lookup[i] then
                        lookup[i] = true
                        ranges[#ranges+1] = i
                    end
                end
            end
        end
    end

    table.sort(ranges)
    return ranges, lookup
end

local function parse_HangulSyllableType()
    local ranges = {}
    local lookup = {}

    for line in io.lines() do
        line = line:gsub("%s*%#.*$", "")
        if line ~= "" then
            local first, last, mark
            first, mark = line:match "^(%x+)%s*%;%s*([%w%s_;]+)%s*$"
            if first then
                last = first
            else
                first, last, mark = line:match "^(%x+)%.%.(%x+)%s*%;%s*([%w%s_;]+)%s*$"
                assert(first, line)
            end

            first = tonumber(first, 16)
            last = tonumber(last, 16)

            for i = first, last do
                if not lookup[i] then
                    lookup[i] = true
                    ranges[#ranges+1] = { cp=i, offset='HANGUL_'..mark }
                end
            end
        end
    end

    table.sort(ranges, function(a, b) return a.cp < b.cp end)
    return ranges
end

local function parse_NormalizationProps(prop, ucd)
    local codepoints = {}

    for line in io.lines() do
        local cps, property, tail = line:match "^([%x%.]+)%s*;%s*([%w%_]+)(.*)$"
        if property == prop then
            local value = tail:match "^%s*;%s*(%w+)"
            local from = cps:match "^%x+"
            local to = cps:match "%.%.(%x+)$"
            if not to then to = from end

            from = tonumber(from, 16)
            to = tonumber(to, 16)

            for cp = from, to, 1 do
                codepoints[#codepoints+1] = cp
            end
        end
    end

    table.sort(codepoints)
    return codepoints
end

local function get_ranges(list, func)
    local first, last, step, offset
    local ranges = {}
    for i = 1, #list do
        local v_cp, v_offset
        local v = list[i]
        local res = not func or func(v)
        if type(v) == 'number' then
            v_cp, v_offset = v, nil
        elseif v.cp then
            v_cp, v_offset = v.cp, v.offset
        end
        if res then
            if first and
                    (not offset or offset == v_offset) and
                    (not step or step == v_cp - last) then
                step = v_cp - last
                last = v_cp
            else
                if first then
                    local r = { first = first, last = last, step = step, offset = offset }
                    ranges[#ranges+1] = r
                end
                first, last, step = v_cp, v_cp, nil
                offset = v_offset
            end
        end
    end
    if first then
        local r = { first = first, last = last, step = step, offset = offset }
        ranges[#ranges+1] = r
    end
    return ranges
end

--[[
local function merge_ranges(...)
    local ranges = {}
    local lookup = {}
    for i = 1, select('#', ...) do
        for _,v in ipairs(select(i, ...)) do
            if not lookup[v] then
                lookup[v] = true
                ranges[#ranges+1] = v
            end
        end
    end
    table.sort(ranges)
    return ranges
end

local function diff_ranges(base, sub, force)
    local ranges = {}
    local lookup = {}
    local missing = {}
    for _, v in ipairs(sub) do
        for i = v.first, v.last, v.step or 1 do
            lookup[i] = true
            missing[i] = true
        end
    end
    for _, v in ipairs(base) do
        for i = v.first, v.last, v.step or 1 do
            if not lookup[i] then
                ranges[#ranges+1] = i
            end
            missing[i] = nil
        end
    end
    if force and next(missing) then
        local m = {}
        for i in pairs(missing) do
            m[#m+1] = i
        end
        table.sort(m)
        for i, v in ipairs(m) do
            m[i] = ("%X"):format(v)
        end
        error(table.concat(m, "\n"))
    end
    return get_ranges(ranges)
end
--]]

local function get_ucd(cp, ucd)
    local data = ucd[cp+1]
    if data.cp > cp then
        local i = cp
        while data.cp > cp do
            data = ucd[i]
            i = i - 1
        end
    end
    return data
end

local function write_ranges(name, ranges)
    io.write("static struct range_table "..name.."_table[] = {\n")
    for _, r in ipairs(ranges) do
        io.write(("    { 0x%X, 0x%X, %d },\n"):format(r.first, r.last, r.step or 1))
    end
    io.write "};\n\n"
end

local function write_convtable(name, conv)
    io.write("static struct conv_table "..name.."_table[] = {\n")
    for _, c in ipairs(conv) do
        io.write(("    { 0x%X, 0x%X, %d, %d },\n"):format(
            c.first, c.last, c.step or 1, c.offset))
    end
    io.write "};\n\n"
end

local function write_canon_cls_table(name, ucd)
    io.write("static struct canon_cls_table "..name.."_table[] = {\n")
    local start, prev = { canon_cls=0 }, { canon_cls=0 }
    for _, data in ipairs(ucd) do
        if data.canon_cls ~= prev.canon_cls then
            if prev.canon_cls ~= 0 then
                io.write(("    { 0x%X, 0x%X, %d },\n"):format(start.cp, prev.cp, prev.canon_cls))
            end
            start = data
        end
        prev = data
    end
    if prev.canon_cls ~= 0 then
        io.write(("    { 0x%X, 0x%X, %d },\n"):format(start.cp, prev.cp, prev.canon_cls))
    end
    io.write "};\n\n"
end

local function write_combine_table(name, tbl)
    local function hash(cp1, cp2)
        return (cp1 * 213) + cp2
    end
    local dup = {}
    for _, c in ipairs(tbl) do
        local cp1, cp2 = table.unpack(c.decomposition)
        if dup[hash(cp1, cp2)] then
            local conflicting = dup[hash(cp1, cp2)]
            local cp3, cp4 = table.unpack(conflicting.decomposition)
            error("Hash collision: "..string.format("%x %x -> %x, %x %x -> %x", cp3, cp4, hash(cp3, cp4), cp1, cp2, hash(cp1, cp2)))
        end
        dup[hash(cp1, cp2)] = c
    end
    table.sort(tbl, function(a,b)
        return hash(table.unpack(a.decomposition)) < hash(table.unpack(b.decomposition))
    end)

    io.write("static struct combine_table "..name.."_table[] = {\n")
    for _, c in ipairs(tbl) do
        local cp1, cp2 = table.unpack(c.decomposition)
        io.write(("    { 0x%X, 0x%X, 0x%X, 0x%X },\n"):format(hash(cp1, cp2), cp1, cp2, c.cp))
    end
    io.write "};\n\n"
end

local function write_decompose_table(name, tbl, ucd)
    table.sort(tbl, function(a,b)
        return a.cp < b.cp
    end)
    io.write("static struct decompose_table "..name.."_table[] = {\n")
    for _, c in ipairs(tbl) do
        local cp1, cp2 = table.unpack(c.decomposition)
        local data = get_ucd(cp2, ucd)
        io.write(("    { 0x%X, 0x%X, 0x%X, %d },\n"):format(c.cp, cp1, cp2, data.canon_cls))
    end
    io.write "};\n\n"
end

local function write_type_table(name, conv)
    io.write("static struct type_table "..name.."_table[] = {\n")
    for _, c in ipairs(conv) do
        if c.step and c.step ~= 1 then
            local i = c.first
            while i <= c.last do
                io.write(("    { 0x%X, 0x%X, %s },\n"):format(i, i, c.offset))
                i = i + c.step
            end
        else
            io.write(("    { 0x%X, 0x%X, %s },\n"):format(c.first, c.last, c.offset))
        end
    end
    io.write "};\n\n"
end


io.output "unidata.h"

io.write [[
/*
 * unidata.h - generated by parseucd.lua
 */
#ifndef unidata_h
#define unidata_h

#ifndef utfint
# define utfint utfint
typedef unsigned int utfint;
#endif

typedef struct range_table {
    utfint first;
    utfint last;
    int step;
} range_table;

typedef struct conv_table {
    utfint first;
    utfint last;
    int step;
    int offset;
} conv_table;

typedef struct nfc_table {
    utfint cp;
    int reason;
    unsigned int data1;
    unsigned int data2;
} nfc_table;

#define REASON_MUST_CONVERT_1 1
#define REASON_MUST_CONVERT_2 2
#define REASON_STARTER_CAN_COMBINE 3
#define REASON_COMBINING_MARK 4
#define REASON_JAMO_VOWEL 5
#define REASON_JAMO_TRAILING 6

typedef struct canon_cls_table {
    utfint first;
    utfint last;
    unsigned int canon_cls;
} canon_cls_table;

typedef struct combine_table {
    utfint hash;
    utfint cp1;
    utfint cp2;
    utfint dest;
} combine_table;

typedef struct decompose_table {
    utfint cp;
    utfint to1;
    utfint to2;
    unsigned int canon_cls2;
} decompose_table;

#define HANGUL_L 1
#define HANGUL_V 2
#define HANGUL_T 3
#define HANGUL_LV 4
#define HANGUL_LVT 5

typedef struct type_table {
    utfint first;
    utfint last;
    int type;
} type_table;

#define INDIC_CONSONANT 1
#define INDIC_LINKER 2
#define INDIC_EXTEND 3

]]

do
    local function ranges(name, f)
        local r = get_ranges((parse_PropList(f)))
        write_ranges(name, r)
    end

    io.input "UCD/DerivedCoreProperties.txt"
    ranges("alpha", "Alphabetic")

    io.input "UCD/DerivedCoreProperties.txt"
    ranges("lower", "Lowercase")

    io.input "UCD/DerivedCoreProperties.txt"
    ranges("upper", "Uppercase")

    io.input "UCD/PropList.txt"
    ranges("xdigit", "Hex_Digit")

    io.input "UCD/PropList.txt"
    ranges("space", "White_Space")

    io.input "UCD/DerivedCoreProperties.txt"
    ranges("unprintable", "Default_Ignorable_Code_Point")

    io.input "UCD/DerivedCoreProperties.txt"
    ranges("graph", "Grapheme_Base")

    io.input "UCD/DerivedCoreProperties.txt"
    ranges("compose", "Grapheme_Extend")

    io.input "UCD/emoji/emoji-data.txt"
    ranges("pictographic", "Extended_Pictographic")
end

do
    io.input "UCD/PropList.txt"
    local prepend = parse_PropList("Prepended_Concatenation_Mark")
    io.input "UCD/IndicSyllabicCategory.txt"
    local indic = parse_PropList({ Consonant_Preceding_Repha=true, Consonant_Prefixed=true })
    for _,cp in ipairs(indic) do
        table.insert(prepend, cp)
    end
    table.sort(prepend)
    write_ranges("prepend", get_ranges(prepend))
end

do
    io.input "UCD/DerivedCoreProperties.txt"
    local linker = parse_PropList("InCB; Linker")
    io.input "UCD/DerivedCoreProperties.txt"
    local consonant = parse_PropList("InCB; Consonant")
    io.input "UCD/DerivedCoreProperties.txt"
    local extend = parse_PropList("InCB; Extend")
    local indic_type = {}
    for _,cp in ipairs(consonant) do table.insert(indic_type, { cp=cp, offset='INDIC_CONSONANT' }) end
    for _,cp in ipairs(linker) do table.insert(indic_type, { cp=cp, offset='INDIC_LINKER' }) end
    for _,cp in ipairs(extend) do table.insert(indic_type, { cp=cp, offset='INDIC_EXTEND' }) end
    table.sort(indic_type, function(a, b) return a.cp < b.cp end)
    write_type_table("indic", get_ranges(indic_type))
end

do
    io.input  "UCD/UnicodeData.txt"
    local ucd = parse_UnicodeData()
    local function set(s)
        local hasht = {}
        for word in s:gmatch "%w%w" do
            hasht[word] = true
        end
        return function(data)
            return hasht[data.gc]
        end
    end
    local function mapping(field)
        return function(data)
            data.offset = nil
            if data[field] then
                data.offset = data[field] - data.cp
                return true
            end
        end
    end
    local cntrl = "Cc Cf"
    local digit = "Nd"
    local alnum_extend = "Nd Nl No"
    local punct = "Sk Sc Sm Pc Pd Ps Pe Pi Pf Po"
    local spacing_mark = "Mc"
    write_ranges("cntrl", get_ranges(ucd, set(cntrl)))
    write_ranges("digit", get_ranges(ucd, set(digit)))
    write_ranges("alnum_extend", get_ranges(ucd, set(alnum_extend)))
    write_ranges("punct", get_ranges(ucd, set(punct)))
    write_ranges("spacing_mark", get_ranges(ucd, set(spacing_mark)))
    write_convtable("tolower", get_ranges(ucd, mapping "lm"))
    write_convtable("toupper", get_ranges(ucd, mapping "um"))
    write_convtable("totitle", get_ranges(ucd, mapping "tm"))
end

do
    io.input "UCD/CaseFolding.txt"
    local mapping = parse_CaseFolding()
    write_convtable("tofold", get_ranges(mapping, function(data)
        data.offset = data.mapping - data.cp
        return true
    end))
end

do
    io.input  "UCD/EastAsianWidth.txt"
    local wide, ambi = parse_EastAsianWidth()
    write_ranges("doublewidth", get_ranges(wide))
    write_ranges("ambiwidth", get_ranges(ambi))
end

do
    io.input "UCD/HangulSyllableType.txt"
    write_type_table("hangul", (get_ranges(parse_HangulSyllableType())))
end

do
    io.input  "UCD/UnicodeData.txt"
    local ucd = parse_UnicodeData()

    -- Write out table of all combining marks
    write_canon_cls_table("nfc_combining", ucd)

    -- Find all primary composites which we may need to consider during NFC normalization
    io.input "UCD/DerivedNormalizationProps.txt"
    local excluded = {}
    for _, cp in ipairs(parse_NormalizationProps('Full_Composition_Exclusion')) do
        excluded[cp] = true
    end
    local composite, can_combine = {}, {}
    for _, data in ipairs(ucd) do
        local decomp = data.decomposition
        if not excluded[data.cp] and decomp and #decomp == 2 then
            table.insert(composite, data)
            can_combine[decomp[2]] = true
        end
    end
    write_combine_table("nfc_composite", composite)
    write_decompose_table("nfc_decompose", composite, ucd)

    io.write("static struct nfc_table nfc_quickcheck_table[] = {\n")

    io.input "UCD/DerivedNormalizationProps.txt"
    for _, cp in ipairs(parse_NormalizationProps('NFC_QC', ucd)) do
        local data = get_ucd(cp, ucd)
        local decomp = data.decomposition
        if decomp then
            if #decomp == 1 then
                local decomp_data = get_ucd(decomp[1], ucd)
                io.write(("    { 0x%X, REASON_MUST_CONVERT_1, 0x%X, %d },\n"):format(data.cp, decomp[1], decomp_data.canon_cls))
            else
                io.write(("    { 0x%X, REASON_MUST_CONVERT_2, 0x%X, 0x%X },\n"):format(data.cp, decomp[1], decomp[2]))
            end
        elseif data.canon_cls ~= 0 then
            io.write(("    { 0x%X, REASON_COMBINING_MARK, 0, 0 },\n"):format(data.cp))
        elseif can_combine[data.cp] then
            io.write(("    { 0x%X, REASON_STARTER_CAN_COMBINE, 0, 0 },\n"):format(data.cp))
        elseif data.cp >= 0x1161 and data.cp <= 0x1175 then
            io.write(("    { 0x%X, REASON_JAMO_VOWEL, 0, 0 },\n"):format(data.cp))
        elseif data.cp >= 0x11A8 and data.cp <= 0x11C2 then
            io.write(("    { 0x%X, REASON_JAMO_TRAILING, 0, 0 },\n"):format(data.cp))
        else
            error("Don't know why we need to check for codepoint "..string.format("0x%x", data.cp).." when doing NFC normalization")
        end
    end

    io.write "};\n\n"
end

io.write "#endif /* unidata_h */\n"
