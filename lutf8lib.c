/* vim: set ft=c nu et sw=2 fdc=2 fdm=syntax : */
#define LUA_LIB
#include <assert.h>
#include <lauxlib.h>
#include <limits.h>
#include <lua.h>
#include <lualib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "unidata.h"

/* UTF-8 string operations */

#define LU_VERSION "0.3.0"

#define LU_BUFFSZ     8
#define LU_UTF8_MAX   0x7FFFFFFFu
#define LU_MAXCP      0x10FFFFu
#define lu_iscontp(p) ((*(p) & 0xC0) == 0x80)

/* clang-format off */
typedef struct lu_Slice { const char *s, *e; } lu_Slice;

static inline lu_Slice lu_newslice(const char *s, size_t len)
{ lu_Slice r; assert(s != NULL); return (r.s = s, r.e = s + len), r; }

static int luU_invalidcp(utfint ch)
{ return (ch > LU_MAXCP || (0xD800u <= ch && ch <= 0xDFFFu)); }
/* clang-format on */

#ifndef LU_QL
# define LU_QL(x) "'" x "'"
#endif

static size_t luU_encode(char *buff, utfint x) {
    int n = 1; /* bytes written so far, counting from the end */
    assert(x <= LU_UTF8_MAX);
    if (x < 0x80)
        buff[LU_BUFFSZ - 1] = x & 0x7F;
    else {
        utfint mfb = 0x3f; /* bits available in the first byte */
        do {
            buff[LU_BUFFSZ - (n++)] = 0x80 | (x & 0x3f);
            x >>= 6;
            mfb >>= 1; /* one less bit remains in the first byte */
        } while (x > mfb);
        buff[LU_BUFFSZ - n] = ((~mfb << 1) | x) & 0xFF;
    }
    return n;
}

static const char *luU_decode(const char *s, utfint *val, int strict) {
    static const utfint limits[] = {~0u,      0x80u,     0x800u,
                                    0x10000u, 0x200000u, 0x4000000u};
    int                 c = s[0] & 0xFF;
    utfint              res = 0;
    if (c < 0x80)
        res = c;
    else {
        int count = 0;
        for (; c & 0x40; c <<= 1) {
            int cc = s[++count] & 0xFF;
            if ((cc & 0xC0) != 0x80) return NULL; /* not a continuation byte */
            res = (res << 6) | (cc & 0x3F);
        }
        res |= ((utfint)(c & 0x7F) << (count * 5));
        if (count > 5 || res > LU_UTF8_MAX || res < limits[count])
            return NULL; /* invalid byte sequence */
        s += count;
    }
    if (strict) {
        /* reject codepoints above U+10FFFF and surrogates */
        if (res > LU_MAXCP || (0xD800u <= res && res <= 0xDFFFu)) return NULL;
    }
    if (val) *val = res;
    return s + 1; /* include the first byte */
}

static const char *luU_prev(const char *s, const char *e) {
    while (s < e && lu_iscontp(e - 1)) --e;
    return s < e ? e - 1 : s;
}

static const char *luU_next(const char *s, const char *e) {
    while (s < e && lu_iscontp(s + 1)) ++s;
    return s < e ? s + 1 : e;
}

static size_t luU_length(lu_Slice s) {
    size_t i;
    for (i = 0; s.s < s.e; ++i) s.s = luU_next(s.s, s.e);
    return i;
}

static const char *luU_offset(lu_Slice s, lua_Integer off, lua_Integer idx) {
    const char *p = s.s + off - 1;
    if (idx >= 0) {
        while (p < s.e && idx > 0) p = luU_next(p, s.e), --idx;
        return idx == 0 ? p : NULL;
    } else {
        while (s.s < p && idx < 0) p = luU_prev(s.s, p), ++idx;
        return idx == 0 ? p : NULL;
    }
}

static const char *luU_relat(lu_Slice s, int idx) {
    if (idx >= 0) return luU_offset(s, 1, idx - 1);
    return luU_offset(s, s.e - s.s + 1, idx);
}

static int luU_range(lu_Slice s, lua_Integer *i, lua_Integer *j) {
    const char *ps = luU_relat(s, (int)*i);
    const char *pe = luU_relat(s, (int)*j);
    *i = (ps ? ps : (*i > 0 ? s.e : s.s)) - s.s;
    *j = (pe ? luU_next(pe, s.e) : (*j > 0 ? s.e : s.s)) - s.s;
    return *i < *j;
}

/* Indexed by top nibble of first byte in code unit */
static uint8_t lu_code_unit_len[] = {1,  1,  1,  1,  1, 1, 1, 1,
                                     -1, -1, -1, -1, 2, 2, 3, 4};

/* Check a multi-byte sequence; return s if invalid, else NULL */
static const char *luU_invalidseq(lu_Slice sl, uint8_t c) {
    const char *s = sl.s, *e = sl.e;
    uint8_t     needed_bytes = lu_code_unit_len[c >> 4];
    uint8_t     c2, c3, c4;
    if (e - s < needed_bytes) return s; /* String is truncated */
    c2 = *(s + 1);
    if ((c2 & 0xC0) != 0x80) return s; /* 2nd byte is not a continuation byte */
    if (needed_bytes >= 3) {
        c3 = *(s + 2);
        if ((c3 & 0xC0) != 0x80)
            return s; /* 3rd byte is not a continuation byte */
        if (needed_bytes == 3) {
            if (c == 0xE0 && c2 < 0xA0)
                return s; /* Overlong 3-byte code unit */
            if (c == 0xED && c2 >= 0xA0)
                return s; /* Reserved codepoint from U+D800-U+DFFF */
        } else {
            c4 = *(s + 3);
            if ((c4 & 0xC0) != 0x80)
                return s; /* 4th byte is not a continuation byte */
            if (c == 0xF0 && c2 < 0x90)
                return s; /* Overlong 4-byte code unit */
            if (c == 0xF4 && c2 >= 0x90)
                return s; /* Illegal codepoint > U+10FFFF */
        }
    }
    return NULL;
}

/* Return pointer to first invalid UTF-8 sequence in 's', or NULL if valid */
static const char *luU_invalidoffset(lu_Slice sl) {
    const char *s = sl.s, *e = sl.e;
    while (s < e) {
        uint8_t c = *s;
        if (c >= 0x80) {
            /* At the start of a sequence:
             * - c < 0xC0: continuation byte, invalid here.
             * - c < 0xC2: overlong 2-byte lead.
             * - c >= 0xF5: invalid codepoint > U+10FFFF or 0xFE/0xFF. */
            if (c < 0xC2 || c >= 0xF5) return s;
            if (luU_invalidseq(lu_newslice(s, e - s), c)) return s;
            s += lu_code_unit_len[c >> 4];
        } else {
            s++;
        }
    }
    return NULL;
}

/* Unicode character categories */

#define lu_tabsize(t) (sizeof(t) / sizeof((t)[0]))

#define lu_categories(X) \
    X('a', alpha)        \
    X('c', cntrl)        \
    X('d', digit)        \
    X('l', lower)        \
    X('p', punct)        \
    X('s', space)        \
    X('t', compose)      \
    X('u', upper)        \
    X('x', xdigit)

#define lu_converters(X) \
    X(lower)             \
    X(upper)             \
    X(title)             \
    X(fold)

static int luT_find(range_table *t, size_t size, utfint ch) {
    size_t begin, end;

    begin = 0;
    end = size;

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        if (t[mid].last < ch)
            begin = mid + 1;
        else if (t[mid].first > ch)
            end = mid;
        else
            return (ch - t[mid].first) % t[mid].step == 0;
    }

    return 0;
}

static int luT_convert(conv_table *t, size_t size, utfint ch) {
    size_t begin, end;

    begin = 0;
    end = size;

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        if (t[mid].last < ch)
            begin = mid + 1;
        else if (t[mid].first > ch)
            end = mid;
        else if ((ch - t[mid].first) % t[mid].step == 0)
            return ch + t[mid].offset;
        else
            return ch;
    }

    return ch;
}

/* Normalization */

static int luN_findcanon(utfint ch) {
    /* The first codepoint with canonicalization class != 0 is U+0300 COMBINING
     * GRAVE ACCENT */
    if (ch < 0x300) {
        return 0;
    }
    size_t begin = 0, end = lu_tabsize(nfc_combining_table);

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        if (nfc_combining_table[mid].last < ch)
            begin = mid + 1;
        else if (nfc_combining_table[mid].first > ch)
            end = mid;
        else
            return nfc_combining_table[mid].canon_cls;
    }

    return 0;
}

static nfc_table *luN_quickcheck(utfint ch) {
    /* The first character which needs to be checked for possible NFC violations
     * is U+0300 COMBINING GRAVE ACCENT */
    size_t begin = 0, end;
    if (ch < 0x300) return NULL;
    end = lu_tabsize(nfc_quickcheck_table);

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        utfint found = nfc_quickcheck_table[mid].cp;
        if (found < ch)
            begin = mid + 1;
        else if (found > ch)
            end = mid;
        else
            return &nfc_quickcheck_table[mid];
    }

    return NULL;
}

static int luN_combine(utfint cp1, utfint cp2, utfint *dest) {
    size_t   begin = 0, end = lu_tabsize(nfc_composite_table);
    unsigned hash = (cp1 * 213) + cp2;

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        utfint val = nfc_composite_table[mid].hash;
        if (val < hash) {
            begin = mid + 1;
        } else if (val > hash) {
            end = mid;
        } else if (
                nfc_composite_table[mid].cp1 == cp1
                && nfc_composite_table[mid].cp2 == cp2) {
            if (dest) *dest = nfc_composite_table[mid].dest;
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}

static decompose_table *luN_decompose(utfint ch) {
    size_t begin = 0, end = lu_tabsize(nfc_decompose_table);

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        utfint found = nfc_decompose_table[mid].cp;
        if (found < ch)
            begin = mid + 1;
        else if (found > ch)
            end = mid;
        else
            return &nfc_decompose_table[mid];
    }

    return NULL;
}

static int luC_mark(utfint ch, utfint starter, int cc, int prevcc) {
    decompose_table *decomp, *decomp2;
    if (cc <= prevcc) return 1;
    if (luN_combine(starter, ch, NULL)) return 0;
    decomp = luN_decompose(starter);
    if (decomp) {
        if (decomp->canon_cls2 > cc && luN_combine(decomp->to1, ch, NULL))
            return 0;
        decomp2 = luN_decompose(decomp->to1);
        if (decomp2 && decomp2->canon_cls2 > cc
            && luN_combine(decomp2->to1, ch, NULL))
            return 0;
    }
    return 1;
}

static int luC_check(
        utfint ch, nfc_table *entry, utfint starter, int cc, int prevcc) {
    assert(entry->reason >= 0 && entry->reason < REASON_MAX);
    switch (entry->reason) {
    case REASON_MUST_CONVERT_1:
    case REASON_MUST_CONVERT_2: return 0;
    case REASON_STARTER_CAN_COMBINE:
        return prevcc || !luN_combine(starter, ch, NULL);
    case REASON_COMBINING_MARK: return luC_mark(ch, starter, cc, prevcc);
    case REASON_JAMO_VOWEL:
        return prevcc || starter < 0x1100 || starter > 0x1112;
    case REASON_JAMO_TRAILING:
        return prevcc || starter < 0xAC00 || starter > 0xD7A3
            || (starter - 0xAC00) % 28 != 0;
    default: return 1;
    }
}

static void luN_merge(
        uint32_t *src1, uint32_t *src2, uint32_t *dest, size_t size1,
        size_t size2) {
    while (size1 && size2) {
        if ((*src1 & 0xFF) > (*src2 & 0xFF))
            *dest++ = *src2++, size2--;
        else
            *dest++ = *src1++, size1--;
    }
    for (; size1; --size1) *dest++ = *src1++;
    for (; size2; --size2) *dest++ = *src2++;
}

/* Merge one bottom-up pass of runs of length 'runsize'; swaps src/dest */
static void luN_mergepass(
        uint32_t **psrc, uint32_t **pdest, size_t size, size_t runsize) {
    uint32_t *src = *psrc, *dest = *pdest, *temp;
    size_t    blocksize = runsize * 2;
    size_t    limit = size & ~(blocksize - 1);
    size_t    i;
    for (i = 0; i < limit; i += blocksize)
        luN_merge(&src[i], &src[i + runsize], &dest[i], runsize, runsize);
    if (size - limit <= runsize)
        memcpy(&dest[limit], &src[limit], (size - limit) * sizeof(uint32_t));
    else
        luN_merge(
                &src[limit], &src[limit + runsize], &dest[limit], runsize,
                size - limit - runsize);
    temp = src, src = dest, dest = temp;
    *psrc = src, *pdest = dest;
}

static void luN_stablesort(uint32_t *vector, uint32_t *scratch, size_t size) {
    /* Stable bottom-up merge sort for combining marks in NFC normalization. */
    uint32_t *src, *dest;
    size_t    limit = size - 1, runsize, i;
    for (i = 0; i < limit; i += 2) {
        if ((vector[i] & 0xFF) > (vector[i + 1] & 0xFF)) {
            uint32_t temp = vector[i];
            vector[i] = vector[i + 1];
            vector[i + 1] = temp;
        }
    }
    if (size <= 2) return;

    runsize = 2, src = vector, dest = scratch;
    while (runsize < size)
        luN_mergepass(&src, &dest, size, runsize), runsize *= 2;
    if (dest == vector) memcpy(vector, scratch, size * sizeof(uint32_t));
}

/* Shuffle item `i` up or down to get it into the right position */
static void luN_stableinsert(uint32_t *v, size_t size, size_t i) {
    uint32_t item = v[i];
    uint32_t cc = item & 0xFF;
    if (i > 0) {
        if (cc < (v[i - 1] & 0xFF)) {
            do {
                v[i] = v[i - 1], i--;
            } while (i > 0 && cc < (v[i - 1] & 0xFF));
            v[i] = item;
            return;
        }
    }
    if (i < size - 1) {
        if (cc > (v[i + 1] & 0xFF)) {
            do {
                v[i] = v[i + 1], i++;
            } while (i < size - 1 && cc > (v[i + 1] & 0xFF));
            v[i] = item;
            return;
        }
    }
}

static void luL_addutf8char(luaL_Buffer *b, utfint ch);

static inline void luV_grow(
        uint32_t **pv, uint32_t *onstack, size_t *size, size_t needed) {
    size_t current_size = *size;
    if (needed >= current_size) {
        /* `needed` is never bigger than `current_size * 2`. */
        size_t    new_size = current_size * 2;
        uint32_t *new_vector = malloc(new_size * sizeof(uint32_t));
        memcpy(new_vector, *pv, current_size * sizeof(uint32_t));
        *size = new_size;
        if (*pv != onstack) free(*pv);
        *pv = new_vector;
    }
}

/*
 * NFC conversion works on one starter plus the following combining-mark run
 * (or a directly following starter).  If the sequence is already NFC we copy
 * it verbatim; otherwise we:
 *   1) prefer precomposed codepoints when possible;
 *   2) stably sort combining marks by canonical class;
 *   3) convert deprecated codepoints to their recommended forms;
 *   4) use precomposed Hangul syllables when possible.
 */
typedef struct lu_NFC {
    lua_State   *L;
    luaL_Buffer *buff;
    const char  *s, *e, *to_copy;
    utfint       starter, ch;
    int          canon_cls, prev_canon_cls, fixedup;
    uint32_t     onstack[8];
    size_t       vec_size, vec_max;
    uint32_t    *vector;
    nfc_table   *entry;
} lu_NFC;

/* Sort accumulated combining marks if they are out of canonical order. */
static void luN_sort(lu_NFC *ctx) {
    size_t i;
    for (i = 1; i < ctx->vec_size; i++) {
        if ((ctx->vector[i - 1] & 0xFF) > (ctx->vector[i] & 0xFF)) {
            uint32_t *scratch = malloc(ctx->vec_size * sizeof(uint32_t));
            luN_stablesort(ctx->vector, scratch, ctx->vec_size);
            free(scratch);
            ctx->fixedup = 1;
            break;
        }
    }
}

/* Handle a combining mark that must become one codepoint; returns continue. */
static int luN_fixmust1(lu_NFC *ctx, size_t i) {
    nfc_table *mark_entry = luN_quickcheck(ctx->vector[i] >> 8);
    ctx->vector[i] = (mark_entry->data1 << 8) | mark_entry->data2;
    ctx->fixedup = 1;
    return 1;
}

/* Handle a combining mark that must become two codepoints; returns continue. */
static int luN_fixmust2(lu_NFC *ctx, size_t i) {
    nfc_table *mark_entry = luN_quickcheck(ctx->vector[i] >> 8);
    luV_grow(&ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 1);
    memmove(&ctx->vector[i + 2], &ctx->vector[i + 1],
            sizeof(uint32_t) * (ctx->vec_size - i - 1));
    ctx->vector[i] = (mark_entry->data1 << 8)
                   | luN_findcanon(mark_entry->data1);
    ctx->vector[i + 1] = (mark_entry->data2 << 8)
                       | luN_findcanon(mark_entry->data2);
    ctx->vec_size++;
    ctx->fixedup = 1;
    return 1;
}

static int luN_fixdecomp2(
        lu_NFC *ctx, size_t i, int markcc, utfint mark,
        decompose_table *decomp) {
    decompose_table *decomp2 = luN_decompose(decomp->to1);
    if (!decomp2 || decomp2->canon_cls2 <= markcc
        || !luN_combine(decomp2->to1, mark, &ctx->starter))
        return 0;
    luV_grow(&ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 1);
    memmove(&ctx->vector[i + 2], &ctx->vector[i + 1],
            sizeof(uint32_t) * (ctx->vec_size - i - 1));
    memmove(&ctx->vector[2], &ctx->vector[0], sizeof(uint32_t) * i);
    ctx->vector[0] = (decomp2->to2 << 8) | luN_findcanon(decomp2->to2);
    ctx->vector[1] = (decomp->to2 << 8) | luN_findcanon(decomp->to2);
    ctx->vec_size++;
    luN_stableinsert(ctx->vector, ctx->vec_size, 1);
    luN_stableinsert(ctx->vector, ctx->vec_size, 0);
    ctx->fixedup = 1;
    return 1;
}

static int luN_fixdecomp(lu_NFC *ctx, size_t i, int markcc, utfint mark) {
    decompose_table *decomp;
    int              class2;
    decomp = luN_decompose(ctx->starter);
    if (!decomp) return 0;
    if (decomp->canon_cls2 > markcc
        && luN_combine(decomp->to1, mark, &ctx->starter)) {
        class2 = luN_findcanon(decomp->to2);
        memmove(&ctx->vector[1], &ctx->vector[0], sizeof(uint32_t) * i);
        ctx->vector[0] = (decomp->to2 << 8) | class2;
        luN_stableinsert(ctx->vector, ctx->vec_size, 0);
        ctx->fixedup = 1;
        return 1;
    }
    return luN_fixdecomp2(ctx, i, markcc, mark, decomp);
}

/* Try to combine/fix one combining mark; returns continue flag. */
static int luN_fix(lu_NFC *ctx, size_t i) {
    uint32_t markcc = ctx->vector[i] & 0xFF;
    utfint   mark = ctx->vector[i] >> 8;
    if (i != 0 && markcc <= (ctx->vector[i - 1] & 0xFF)) return 0;
    if (luN_combine(ctx->starter, mark, &ctx->starter)) {
        ctx->vec_size--;
        memmove(&ctx->vector[i], &ctx->vector[i + 1],
                sizeof(uint32_t) * (ctx->vec_size - i));
        ctx->fixedup = 1;
        return 1;
    }
    return luN_fixdecomp(ctx, i, markcc, mark);
}

/* Fix one vector entry; returns 1 when the index must not advance. */
static int luN_fixone(lu_NFC *ctx, size_t i) {
    nfc_table *mark_entry = luN_quickcheck(ctx->vector[i] >> 8);
    if (!mark_entry) return 0;
    switch (mark_entry->reason) {
    case REASON_MUST_CONVERT_1: return luN_fixmust1(ctx, i);
    case REASON_MUST_CONVERT_2: return luN_fixmust2(ctx, i);
    case REASON_COMBINING_MARK: return luN_fix(ctx, i);
    default: return 0;
    }
}

static void luN_emit(lu_NFC *ctx) {
    size_t i;
    if (ctx->fixedup) {
        if (ctx->starter != (utfint)-1)
            luL_addutf8char(ctx->buff, ctx->starter);
        for (i = 0; i < ctx->vec_size; i++)
            luL_addutf8char(ctx->buff, ctx->vector[i] >> 8);
    } else {
        luaL_addlstring(ctx->buff, ctx->to_copy, ctx->s - ctx->to_copy);
    }
}

/* Process accumulated combining marks and emit the preceding sequence. */
static int luN_process(lu_NFC *ctx) {
    size_t i = 0;
    luN_sort(ctx);
    while (i < ctx->vec_size)
        if (!luN_fixone(ctx, i)) ++i;
    luN_emit(ctx);
    if (ctx->s >= ctx->e) return 1;
    return (ctx->vec_size = 0, ctx->fixedup = 0), 0;
}

static void luN_accumulate(lu_NFC *ctx) {
    luV_grow(&ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 1);
    ctx->vector[ctx->vec_size++] = (ctx->ch << 8) | (ctx->canon_cls & 0xFF);
}

/* Handle a deprecated starter that splits into two combining marks. */
static int luN_splitstarter(lu_NFC *ctx, const char *new_s) {
    utfint conv1, conv2;
    int    cc1, cc2;
    if (!ctx->entry || ctx->entry->reason != REASON_MUST_CONVERT_2) return 0;
    conv1 = ctx->entry->data1;
    cc1 = luN_findcanon(conv1);
    if (!cc1) return 0;
    conv2 = ctx->entry->data2;
    cc2 = luN_findcanon(conv2);
    luV_grow(&ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 2);
    ctx->vector[ctx->vec_size++] = (conv1 << 8) | (cc1 & 0xFF);
    ctx->vector[ctx->vec_size++] = (conv2 << 8) | (cc2 & 0xFF);
    ctx->s = new_s;
    ctx->prev_canon_cls = cc2;
    ctx->fixedup = 1;
    return 1;
}

/* Handle a starter that directly follows another starter. */
static void luN_nextstarter(lu_NFC *ctx) {
    ctx->fixedup = 0;
    if (ctx->entry) {
        if (ctx->entry->reason == REASON_STARTER_CAN_COMBINE
            && luN_combine(ctx->starter, ctx->ch, &ctx->ch)) {
            ctx->fixedup = 1;
        } else if (
                ctx->entry->reason == REASON_JAMO_VOWEL
                && ctx->starter >= 0x1100 && ctx->starter <= 0x1112) {
            ctx->ch = 0xAC00 + ((ctx->starter - 0x1100) * 588)
                    + ((ctx->ch - 0x1161) * 28);
            ctx->fixedup = 1;
        } else if (ctx->entry->reason == REASON_JAMO_TRAILING) {
            if (ctx->starter >= 0xAC00 && ctx->starter <= 0xD7A3
                && (ctx->starter - 0xAC00) % 28 == 0) {
                ctx->ch = ctx->starter + ctx->ch - 0x11A7;
                ctx->fixedup = 1;
            }
        }
    }
    if (!ctx->fixedup) luL_addutf8char(ctx->buff, ctx->starter);
}

static void luN_splitconvert(
        lu_NFC *ctx, utfint conv1, utfint conv2, int cc2, int cc3) {
    nfc_table *conv_entry = luN_quickcheck(conv1);
    utfint     conv3;
    if (conv_entry && conv_entry->reason == REASON_MUST_CONVERT_2) {
        conv3 = conv2;
        conv1 = conv_entry->data1;
        conv2 = conv_entry->data2;
        cc2 = luN_findcanon(conv2);
        if (cc2) {
            ctx->starter = conv1;
            ctx->vector[0] = (conv2 << 8) | cc2;
            ctx->vector[1] = (conv3 << 8) | cc3;
            ctx->vec_size = 2;
        } else {
            luL_addutf8char(ctx->buff, conv1);
            ctx->starter = conv2;
            ctx->vector[0] = (conv3 << 8) | cc3;
            ctx->vec_size = 1;
        }
        ctx->canon_cls = cc3;
    } else {
        ctx->starter = conv1;
        ctx->vector[0] = (conv2 << 8) | cc2;
        ctx->vec_size = 1;
        ctx->canon_cls = cc2;
    }
    ctx->fixedup = 1;
}

/* Convert a starter to its canonical variant, if needed. */
static void luN_convertstarter(lu_NFC *ctx) {
    utfint conv1, conv2;
    int    cc2;
    if (!ctx->entry) return;
    if (ctx->entry->reason == REASON_MUST_CONVERT_1) {
        ctx->starter = ctx->entry->data1;
        ctx->fixedup = 1;
        return;
    }
    if (ctx->entry->reason != REASON_MUST_CONVERT_2) return;
    conv1 = ctx->entry->data1;
    conv2 = ctx->entry->data2;
    cc2 = luN_findcanon(conv2);
    if (!cc2) {
        luL_addutf8char(ctx->buff, conv1);
        ctx->starter = conv2;
        ctx->fixedup = 1;
        return;
    }
    luN_splitconvert(ctx, conv1, conv2, cc2, cc2);
}

/* Handle a starter codepoint; returns 1 to continue, 2 when finished. */
static int luN_starter(lu_NFC *ctx, const char *new_s) {
    ctx->entry = luN_quickcheck(ctx->ch);
    if (luN_splitstarter(ctx, new_s)) return 1;
    if (ctx->prev_canon_cls) {
        if (luN_process(ctx)) return 2;
    } else if (ctx->starter != (utfint)-1) {
        luN_nextstarter(ctx);
    }
    ctx->starter = ctx->ch;
    ctx->to_copy = ctx->s;
    luN_convertstarter(ctx);
    return 0;
}

static void luN_init(lu_NFC *c, lua_State *L, luaL_Buffer *b, lu_Slice v) {
    c->L = L;
    c->buff = b;
    c->s = v.s;
    c->e = v.e;
    c->to_copy = v.s;
    c->starter = (utfint)-1;
    c->ch = 0;
    c->canon_cls = 0;
    c->prev_canon_cls = 0;
    c->fixedup = 0;
    c->vec_size = 0;
    c->vec_max = sizeof(c->onstack) / sizeof(uint32_t);
    c->vector = c->onstack;
    c->entry = NULL;
}

static void luN_free(lu_NFC *ctx) {
    if (ctx->vector != ctx->onstack) free(ctx->vector);
}

static void luN_run(lu_NFC *ctx) {
    int r;
    while (ctx->s < ctx->e) {
        const char *new_s = luU_decode(ctx->s, &ctx->ch, 1);
        assert(new_s != NULL);
        ctx->canon_cls = luN_findcanon(ctx->ch);
        if (!ctx->canon_cls) {
            r = luN_starter(ctx, new_s);
            if (r == 1) continue;
            if (r == 2) {
                luN_free(ctx);
                return;
            }
        } else {
            luN_accumulate(ctx);
        }
        ctx->s = new_s;
        ctx->prev_canon_cls = ctx->canon_cls;
    }
    if (ctx->vec_size && luN_process(ctx)) {
        luN_free(ctx);
        return;
    }
    if (ctx->starter != (utfint)-1) luL_addutf8char(ctx->buff, ctx->starter);
    luN_free(ctx);
}

static void luN_fromstring(lua_State *L, luaL_Buffer *b, lu_Slice v) {
    lu_NFC ctx;
    luN_init(&ctx, L, b, v);
    luN_run(&ctx);
}

/* Grapheme cluster support */

static int luG_hangultype(utfint ch) {
    /* The first Hangul codepoint is U+1100 */
    if (ch < 0x1100) {
        return 0;
    }
    size_t begin = 0, end = lu_tabsize(hangul_table);

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        if (hangul_table[mid].last < ch)
            begin = mid + 1;
        else if (hangul_table[mid].first > ch)
            end = mid;
        else
            return hangul_table[mid].type;
    }

    return 0;
}

static int luG_indictype(utfint ch) {
    /* The first Indic conjunct codepoint is U+0300 */
    if (ch < 0x300) {
        return 0;
    }
    size_t begin = 0, end = lu_tabsize(indic_table);

    while (begin < end) {
        size_t mid = (begin + end) / 2;
        if (indic_table[mid].last < ch)
            begin = mid + 1;
        else if (indic_table[mid].first > ch)
            end = mid;
        else
            return indic_table[mid].type;
    }

    return 0;
}

#define X(cls, name)                                                 \
    static int luT_is##name(utfint ch) {                             \
        return luT_find(name##_table, lu_tabsize(name##_table), ch); \
    }
lu_categories(X)
#undef X

#define X(name)                                                      \
    static utfint lu_to##name(utfint ch) {                           \
        return luT_convert(                                          \
                to##name##_table, lu_tabsize(to##name##_table), ch); \
    }
        lu_converters(X)
#undef X

                static int luT_isgraph(utfint ch) {
    if (luT_find(space_table, lu_tabsize(space_table), ch)) return 0;
    if (luT_find(graph_table, lu_tabsize(graph_table), ch)) return 1;
    if (luT_find(compose_table, lu_tabsize(compose_table), ch)) return 1;
    return 0;
}

static int luT_isalnum(utfint ch) {
    if (luT_find(alpha_table, lu_tabsize(alpha_table), ch)) return 1;
    if (luT_find(alnum_extend_table, lu_tabsize(alnum_extend_table), ch))
        return 1;
    return 0;
}

static int luW_width(utfint ch, int ambiwidth, int default_width) {
    if (luT_find(unprintable_table, lu_tabsize(unprintable_table), ch))
        return default_width;
    if (luT_find(compose_table, lu_tabsize(compose_table), ch))
        return default_width;
    if (luT_find(doublewidth_table, lu_tabsize(doublewidth_table), ch))
        return 2;
    if (luT_find(ambiwidth_table, lu_tabsize(ambiwidth_table), ch))
        return ambiwidth;
    return 1;
}

/* string module compatible interface */

/* clang-format off */
static int luL_typeerror(lua_State *L, int idx, const char *tname)
{ return luaL_error(L, "%s expected, got %s", tname, luaL_typename(L, idx)); }
/* clang-format on */

static lu_Slice lu_checkslice(lua_State *L, int idx) {
    size_t      len;
    const char *s = luaL_checklstring(L, idx, &len);
    return lu_newslice(s, len);
}

static lu_Slice lu_toslice(lua_State *L, int idx) {
    size_t      len;
    const char *s = lua_tolstring(L, idx, &len);
    return lu_newslice(s, len);
}

static const char *luU_decodechecked(lua_State *L, const char *p, utfint *pv) {
    *pv = 0, p = luU_decode(p, pv, 0);
    if (p == NULL) luaL_error(L, "invalid UTF-8 code");
    return p;
}

static void luL_addutf8char(luaL_Buffer *b, utfint ch) {
    char   buff[LU_BUFFSZ];
    size_t n = luU_encode(buff, ch);
    luaL_addlstring(b, buff + LU_BUFFSZ - n, n);
}

static lua_Integer luB_relat(lua_Integer pos, size_t len) {
    if (pos >= 0)
        return pos;
    else if (0u - (size_t)pos > len)
        return 0;
    else
        return (lua_Integer)len + pos + 1;
}

static void luB_range(
        lua_State *L, size_t len, lua_Integer *posi, lua_Integer *posj) {
    luaL_argcheck(
            L, 1 <= *posi && --*posi <= (lua_Integer)len, 2,
            "initial position out of bounds");
    luaL_argcheck(
            L, --*posj < (lua_Integer)len, 3, "final position out of bounds");
}

static int Lutf8_len(lua_State *L) {
    size_t      len, n;
    const char *s = luaL_checklstring(L, 1, &len), *p, *e;
    lua_Integer posi = luB_relat(luaL_optinteger(L, 2, 1), len);
    lua_Integer posj = luB_relat(luaL_optinteger(L, 3, len), len);
    int         lax = lua_toboolean(L, 4);
    luB_range(L, len, &posi, &posj);
    for (n = 0, p = s + posi, e = s + posj + 1; p < e; ++n) {
        if (lax)
            p = luU_next(p, e);
        else {
            utfint      ch;
            const char *np = luU_decode(p, &ch, !lax);
            if (np == NULL || luU_invalidcp(ch))
                return lua_pushnil(L), lua_pushinteger(L, p - s + 1), 2;
            p = np;
        }
    }
    lua_pushinteger(L, n);
    return 1;
}

static int Lutf8_sub(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer posi = luaL_checkinteger(L, 2);
    lua_Integer posj = luaL_optinteger(L, 3, -1);
    if (luU_range(lu_newslice(s, e - s), &posi, &posj))
        lua_pushlstring(L, s + posi, posj - posi);
    else
        lua_pushliteral(L, "");
    return 1;
}

static int Lutf8_reverse(lua_State *L) {
    luaL_Buffer b;
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *prev, *pprev, *ends, *e = sl.e, *s = sl.s;
    (void)ends;
    int lax = lua_toboolean(L, 2);
    luaL_buffinit(L, &b);
    if (lax) {
        for (prev = e; s < prev; e = prev) {
            prev = luU_prev(s, prev);
            luaL_addlstring(&b, prev, e - prev);
        }
    } else {
        for (prev = e; s < prev; prev = pprev) {
            utfint code = 0;
            ends = luU_decodechecked(L, pprev = luU_prev(s, prev), &code);
            assert(ends == prev);
            if (luU_invalidcp(code)) return luaL_error(L, "invalid UTF-8 code");
            if (!luT_iscompose(code)) {
                luaL_addlstring(&b, pprev, e - pprev);
                e = pprev;
            }
        }
    }
    luaL_pushresult(&b);
    return 1;
}

static int Lutf8_byte(lua_State *L) {
    size_t      n = 0;
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer posi = luaL_optinteger(L, 2, 1);
    lua_Integer posj = luaL_optinteger(L, 3, posi);
    if (luU_range(lu_newslice(s, e - s), &posi, &posj)) {
        for (e = s + posj, s = s + posi; s < e; ++n) {
            utfint ch = 0;
            s = luU_decodechecked(L, s, &ch);
            lua_pushinteger(L, ch);
        }
    }
    return (int)n;
}

static int Lutf8_codepoint(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    size_t      len = e - s;
    lua_Integer posi = luB_relat(luaL_optinteger(L, 2, 1), len);
    lua_Integer posj = luB_relat(luaL_optinteger(L, 3, posi), len);
    int         lax = lua_toboolean(L, 4);
    int         n;
    const char *se;
    luaL_argcheck(L, posi >= 1, 2, "out of bounds");
    luaL_argcheck(L, posj <= (lua_Integer)len, 3, "out of bounds");
    if (posi > posj) return 0;  /* empty interval */
    if (posj - posi >= INT_MAX) /* (lua_Integer -> int) overflow? */
        return luaL_error(L, "string slice too long");
    n = (int)(posj - posi + 1);
    luaL_checkstack(L, n, "string slice too long");
    n = 0;
    se = s + posj;
    for (n = 0, s += posi - 1; s < se;) {
        utfint code = 0;
        s = luU_decodechecked(L, s, &code);
        if (!lax && luU_invalidcp(code))
            return luaL_error(L, "invalid UTF-8 code");
        lua_pushinteger(L, code);
        n++;
    }
    return n;
}

static int Lutf8_char(lua_State *L) {
    int         i, n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    for (i = 1; i <= n; ++i) {
        utfint code = (utfint)luaL_checkinteger(L, i);
        luaL_argcheck(L, code <= LU_MAXCP, i, "value out of range");
        luL_addutf8char(&b, (utfint)code);
    }
    luaL_pushresult(&b);
    return 1;
}

#define X(name)                                                           \
    static int Lutf8_##name(lua_State *L) {                               \
        int t = lua_type(L, 1);                                           \
        if (t == LUA_TNUMBER)                                             \
            lua_pushinteger(L, lu_to##name((utfint)lua_tointeger(L, 1))); \
        else if (t == LUA_TSTRING) {                                      \
            luaL_Buffer b;                                                \
            lu_Slice    sl = lu_toslice(L, 1);                            \
            const char *s = sl.s, *e = sl.e;                              \
            luaL_buffinit(L, &b);                                         \
            while (s < e) {                                               \
                utfint ch = 0;                                            \
                s = luU_decodechecked(L, s, &ch);                         \
                luL_addutf8char(&b, lu_to##name(ch));                     \
            }                                                             \
            luaL_pushresult(&b);                                          \
        } else                                                            \
            return luL_typeerror(L, 1, "number/string");                  \
        return 1;                                                         \
    }
lu_converters(X)
#undef X

        /* unicode extra interface */

        static void luE_parse(
                lua_State *L, lu_Slice *sl, int hex, utfint *pch) {
    const char *s = sl->s, *e = sl->e;
    utfint      code = 0;
    int         in_bracket = 0, closed = 0, digits = 0;
    if (*s == '{') ++s, in_bracket = 1;
    for (; s < e; ++s) {
        utfint ch = (unsigned char)*s;
        if (ch >= '0' && ch <= '9')
            ch = ch - '0';
        else if (hex && ch >= 'A' && ch <= 'F')
            ch = 10 + (ch - 'A');
        else if (hex && ch >= 'a' && ch <= 'f')
            ch = 10 + (ch - 'a');
        else if (in_bracket && ch == '}') {
            ++s;
            closed = 1;
            break;
        } else if (!in_bracket) {
            if (digits == 0) luaL_error(L, "invalid escape '%c'", ch);
            break;
        } else
            luaL_error(L, "invalid escape '%c'", ch);
        code *= hex ? 16 : 10;
        code += ch;
        digits++;
    }
    if (in_bracket && !closed) luaL_error(L, "unfinished escape");
    if (!digits) luaL_error(L, "invalid escape: expected digit");
    *pch = code;
    sl->s = s;
}

static int luE_prefix(lua_State *L, lu_Slice *sl, utfint *ch) {
    const char *s = sl->s, *e = sl->e;
    int         hex = 0;
    if (s >= e) luaL_error(L, "unfinished escape");
    switch (*s) {
        /* clang-format off */
    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
    case '8': case '9': case '{':
        break;
    /* clang-format on */
    case 'x':
    case 'X': hex = 1; /* FALLTHROUGH */
    case 'u':
    case 'U':
        if (s + 1 < e) {
            ++s;
            break;
        } /* FALLTHROUGH */
    default:
        s = luU_decodechecked(L, s, ch);
        sl->s = s;
        return 0;
    }
    sl->s = s;
    luE_parse(L, sl, hex, ch);
    return 1;
}

static int Lutf8_escape(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    while (sl.s < sl.e) {
        utfint ch = 0;
        sl.s = luU_decodechecked(L, sl.s, &ch);
        if (ch == '%') luE_prefix(L, &sl, &ch);
        luL_addutf8char(&b, ch);
    }
    luaL_pushresult(&b);
    return 1;
}

static int Lutf8_insert(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    size_t      sublen;
    const char *subs;
    luaL_Buffer b;
    int         nargs = 2;
    const char *first = e;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        int idx = (int)lua_tointeger(L, 2);
        if (idx != 0) first = luU_relat(lu_newslice(s, e - s), idx);
        luaL_argcheck(L, first, 2, "invalid index");
        ++nargs;
    }
    subs = luaL_checklstring(L, nargs, &sublen);
    luaL_buffinit(L, &b);
    luaL_addlstring(&b, s, first - s);
    luaL_addlstring(&b, subs, sublen);
    luaL_addlstring(&b, first, e - first);
    luaL_pushresult(&b);
    return 1;
}

static int Lutf8_remove(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer posi = luaL_optinteger(L, 2, -1);
    lua_Integer posj = luaL_optinteger(L, 3, -1);
    luaL_Buffer b;
    if (!luU_range(lu_newslice(s, e - s), &posi, &posj))
        return lua_settop(L, 1), 1;
    luaL_buffinit(L, &b);
    luaL_addlstring(&b, s, posi);
    luaL_addlstring(&b, s + posj, e - s - posj);
    return luaL_pushresult(&b), 1;
}

static int lu_pushoffset(
        lua_State *L, lu_Slice v, lua_Integer o, lua_Integer i) {
    utfint      ch = 0;
    const char *p;
    if (i != 0)
        p = luU_offset(v, o, i);
    else if (p = v.s + o - 1, lu_iscontp(p))
        p = luU_prev(v.s, p);
    if (p == NULL || p == v.e) return 0;
    luU_decode(p, &ch, 0);
    return lua_pushinteger(L, p - v.s + 1), lua_pushinteger(L, ch), 2;
}

static int Lutf8_charpos(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer offset = 1;
    if (lua_isnoneornil(L, 3)) {
        lua_Integer idx = luaL_optinteger(L, 2, 0);
        if (idx > 0)
            --idx;
        else if (idx < 0)
            offset = e - s + 1;
        return lu_pushoffset(L, sl, offset, idx);
    }
    offset = luB_relat(luaL_optinteger(L, 2, 1), e - s);
    if (offset < 1) offset = 1;
    return lu_pushoffset(L, sl, offset, luaL_checkinteger(L, 3));
}

static void lu_moveback(const char *s, lua_Integer *pposi, lua_Integer *pn) {
    lua_Integer posi = *pposi, n = *pn;
    while (n < 0 && posi > 0) {
        do {
            posi--;
        } while (posi > 0 && lu_iscontp(s + posi)); /* skip continuations */
        n++;
    }
    *pposi = posi;
    *pn = n;
}

static void lu_moveforward(
        const char *s, lua_Integer len, lua_Integer *pposi, lua_Integer *pn) {
    lua_Integer posi = *pposi, n = *pn;
    n--; /* current position is already on the first character */
    while (n > 0 && posi < len) {
        do {
            posi++;
        } while (lu_iscontp(s + posi)); /* skip continuation bytes */
        n--;
    }
    *pposi = posi;
    *pn = n;
}

static lua_Integer lu_endoffset(const char *s, lua_Integer posi) {
    if ((s[posi] & 0x80) != 0) {
        do {
            posi++;
        } while (lu_iscontp(s + posi + 1));
    }
    /* else one-byte character: final position is the initial one */
    return posi + 1;
}

static int Lutf8_offset(lua_State *L) {
    size_t      len;
    const char *s = luaL_checklstring(L, 1, &len);
    lua_Integer n = luaL_checkinteger(L, 2);
    lua_Integer posi = (n >= 0) ? 1 : len + 1;
    posi = luB_relat(luaL_optinteger(L, 3, posi), len);
    luaL_argcheck(
            L, 1 <= posi && --posi <= (lua_Integer)len, 3,
            "position out of range");
    if (n == 0) {
        /* find beginning of current byte sequence */
        while (posi > 0 && lu_iscontp(s + posi)) posi--;
    } else {
        if (lu_iscontp(s + posi))
            return luaL_error(L, "initial position is a continuation byte");
        if (n < 0)
            lu_moveback(s, &posi, &n);
        else
            lu_moveforward(s, (lua_Integer)len, &posi, &n);
    }
    if (n != 0) return lua_pushnil(L), 1;
    lua_pushinteger(L, posi + 1);
    lua_pushinteger(L, lu_endoffset(s, posi));
    return 2;
}

static int Lutf8_next(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer offset = luB_relat(luaL_optinteger(L, 2, 1), e - s);
    lua_Integer idx = luaL_optinteger(L, 3, !lua_isnoneornil(L, 2));
    return lu_pushoffset(L, sl, offset, idx);
}

static int lu_iteraux(lua_State *L, int strict) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    int         n = (int)lua_tointeger(L, 2);
    const char *p = n <= 0 ? s : luU_next(s + n - 1, e);
    if (p < e) {
        utfint code = 0;
        luU_decodechecked(L, p, &code);
        if (strict && luU_invalidcp(code))
            return luaL_error(L, "invalid UTF-8 code");
        return lua_pushinteger(L, p - s + 1), lua_pushinteger(L, code), 2;
    }
    return 0; /* no more codepoints */
}

static int luL_iterstrict(lua_State *L) { return lu_iteraux(L, 1); }
static int luL_iterlax(lua_State *L) { return lu_iteraux(L, 0); }

static int Lutf8_codes(lua_State *L) {
    int lax = lua_toboolean(L, 2);
    luaL_checkstring(L, 1);
    lua_pushcfunction(L, lax ? luL_iterlax : luL_iterstrict);
    lua_pushvalue(L, 1);
    lua_pushinteger(L, 0);
    return 3;
}

static int luW_opt(lua_State *L, int idx, int *pdefault) {
    int ambiwidth = (int)luaL_optinteger(L, idx, 1);
    if (pdefault != NULL) *pdefault = (int)luaL_optinteger(L, idx + 1, 0);
    return ambiwidth;
}

static int luW_string(lua_State *L) {
    size_t      len;
    const char *e, *s = luaL_checklstring(L, 1, &len);
    lua_Integer posi = luB_relat(luaL_optinteger(L, 2, 1), len);
    lua_Integer posj = luB_relat(luaL_optinteger(L, 3, len), len);
    int         width = 0, ambiwidth, default_width;
    ambiwidth = luW_opt(L, 4, &default_width);
    luaL_argcheck(
            L, 1 <= posi && --posi <= (lua_Integer)len, 2,
            "initial position out of bounds");
    luaL_argcheck(
            L, --posj < (lua_Integer)len, 3, "final position out of bounds");
    e = s + posj + 1, s += posi;
    while (s < e) {
        utfint ch = 0;
        s = luU_decodechecked(L, s, &ch);
        width += luW_width(ch, ambiwidth, default_width);
    }
    return lua_pushinteger(L, (lua_Integer)width), 1;
}

static int Lutf8_width(lua_State *L) {
    int t = lua_type(L, 1);
    int ambiwidth, default_width, w;
    if (t != LUA_TNUMBER && t != LUA_TSTRING)
        return luL_typeerror(L, 1, "number/string");
    if (t == LUA_TSTRING) return luW_string(L);
    ambiwidth = luW_opt(L, 2, &default_width);
    w = luW_width((utfint)lua_tointeger(L, 1), ambiwidth, default_width);
    return lua_pushinteger(L, w), 1;
}

static int Lutf8_widthindex(lua_State *L) {
    size_t      len;
    const char *e, *s = luaL_checklstring(L, 1, &len);
    int         chwidth, width = (int)luaL_checkinteger(L, 2);
    lua_Integer posi = luB_relat(luaL_optinteger(L, 3, 1), len);
    lua_Integer posj = luB_relat(luaL_optinteger(L, 4, len), len), idx;
    int         default_width, ambiwidth = luW_opt(L, 5, &default_width);
    luB_range(L, len, &posi, &posj);
    for (idx = 0, e = s + posj + 1, s += posi; s < e; ++idx, width -= chwidth) {
        utfint ch = 0;
        s = luU_decodechecked(L, s, &ch);
        chwidth = luW_width(ch, ambiwidth, default_width);
        if (width <= chwidth) {
            lua_pushinteger(L, idx + 1);
            lua_pushinteger(L, width);
            lua_pushinteger(L, chwidth);
            return 3;
        }
    }
    return lua_pushinteger(L, idx), 1;
}

static int Lutf8_widthlimit(lua_State *L) {
    size_t      len;
    const char *s, *e, *n, *h = luaL_checklstring(L, 1, &len);
    lua_Integer width = luaL_checkinteger(L, 2);
    lua_Integer posi = luB_relat(luaL_optinteger(L, 3, 1), len);
    lua_Integer posj = luB_relat(luaL_optinteger(L, 4, len), len);
    int    chwidth, default_width, ambiwidth = luW_opt(L, 5, &default_width);
    utfint ch;
    luB_range(L, len, &posi, &posj);
    s = h + posi, e = h + posj + 1;
    if (width >= 0) {
        for (; s < e && width != 0; s = n, width -= chwidth) {
            n = luU_decodechecked(L, s, &ch);
            chwidth = luW_width(ch, ambiwidth, default_width);
            if (width < chwidth) break;
        }
        lua_pushinteger(L, s - h);
    } else {
        for (; s < e && width != 0; e = n, width += chwidth) {
            luU_decodechecked(L, n = luU_prev(s, e), &ch);
            chwidth = luW_width(ch, ambiwidth, default_width);
            if (-width < chwidth) break;
        }
        lua_pushinteger(L, e - h + 1);
    }
    lua_pushinteger(L, width);
    return 2;
}

static int Lutf8_ncasecmp(lua_State *L) {
    lu_Slice    sl1 = lu_checkslice(L, 1);
    const char *s1 = sl1.s, *e1 = sl1.e;
    lu_Slice    sl2 = lu_checkslice(L, 2);
    const char *s2 = sl2.s, *e2 = sl2.e;
    while (s1 < e1 || s2 < e2) {
        utfint ch1 = 0, ch2 = 0;
        if (s1 == e1)
            ch2 = 1;
        else if (s2 == e2)
            ch1 = 1;
        else {
            s1 = luU_decodechecked(L, s1, &ch1);
            s2 = luU_decodechecked(L, s2, &ch2);
            ch1 = lu_tofold(ch1), ch2 = lu_tofold(ch2);
        }
        if (ch1 != ch2) {
            lua_pushinteger(L, ch1 > ch2 ? 1 : -1);
            return 1;
        }
    }
    lua_pushinteger(L, 0);
    return 1;
}

/* utf8 pattern matching implement */

#ifndef LU_MAXCAPTURES
# define LU_MAXCAPTURES 32
#endif /* LU_MAXCAPTURES */

#define LU_CAP_UNFINISHED (-1)
#define LU_CAP_POSITION   (-2)

typedef struct lu_MatchState {
    int matchdepth; /* control for recursive depth (to avoid C stack overflow)
                     */
    const char  *src_init;  /* init of source string */
    const char  *src_end;   /* end ('\0') of source string */
    const char  *p;         /* current pattern start */
    const char  *p_end;     /* end ('\0') of pattern */
    int          tr;        /* replacement type for gsub */
    lua_Integer *pn;        /* substitution counter for gsub */
    const char  *lastmatch; /* end of last match in gsub */
    int          changed;   /* whether gsub changed the string */
    lua_State   *L;
    int          level; /* total number of captures (finished or unfinished) */
    struct {
        const char *init;
        ptrdiff_t   len;
    } capture[LU_MAXCAPTURES];
} lu_MatchState;

/* recursive function */
static const char *luM_match(lu_MatchState *ms, const char *s, const char *p);

/* maximum recursion depth for 'match' */
#if !defined(LU_MAXCCALLS)
#define LU_MAXCCALLS 200
#endif

#define LU_ESC      '%'
#define LU_SPECIALS "^$*+?.([%-"

static int luM_checkcapture(lu_MatchState *ms, int l) {
    l -= '1';
    if (l < 0 || l >= ms->level || ms->capture[l].len == LU_CAP_UNFINISHED)
        return luaL_error(ms->L, "invalid capture index %%%d", l + 1);
    return l;
}

static int luM_toclosecapture(lu_MatchState *ms) {
    int level = ms->level;
    while (--level >= 0)
        if (ms->capture[level].len == LU_CAP_UNFINISHED) return level;
    return luaL_error(ms->L, "invalid pattern capture");
}

static const char *luM_classend(lu_MatchState *ms, const char *p) {
    utfint ch = 0;
    p = luU_decodechecked(ms->L, p, &ch);
    switch (ch) {
    case LU_ESC:
        if (p == ms->p_end)
            luaL_error(ms->L, "malformed pattern (ends with " LU_QL("%%") ")");
        return luU_next(p, ms->p_end);
    case '[':
        if (*p == '^') p++;
        do { /* look for a `]' */
            if (p == ms->p_end)
                luaL_error(ms->L, "malformed pattern (missing " LU_QL("]") ")");
            if (*(p++) == LU_ESC && p < ms->p_end)
                p++; /* skip escapes (e.g. `%]') */
        } while (*p != ']');
        return p + 1;
    default: return p;
    }
}

static int luM_class(utfint c, utfint cl) {
    int res;
    switch (lu_tolower(cl)) {
#define X(cls, name) \
    case cls: res = luT_is##name(c); break;
    lu_categories(X)
#undef X
            case 'g':
        res = luT_isgraph(c);
        break;
    case 'w': res = luT_isalnum(c); break;
    case 'z': res = (c == 0); break; /* deprecated option */
    default: return (cl == c);
    }
    return (luT_islower(cl) ? res : !res);
}

static int luM_bracketclass(
        lu_MatchState *ms, utfint c, const char *p, const char *ec) {
    int sig = 1;
    assert(*p == '[');
    if (*++p == '^') {
        sig = 0;
        p++; /* skip the `^' */
    }
    while (p < ec) {
        utfint ch = 0;
        p = luU_decodechecked(ms->L, p, &ch);
        if (ch == LU_ESC) {
            p = luU_decodechecked(ms->L, p, &ch);
            if (luM_class(c, ch)) return sig;
        } else {
            utfint      next = 0;
            const char *np = luU_decodechecked(ms->L, p, &next);
            if (next == '-' && np < ec) {
                p = luU_decodechecked(ms->L, np, &next);
                if (ch <= c && c <= next) return sig;
            } else if (ch == c)
                return sig;
        }
    }
    return !sig;
}

static int luM_single(
        lu_MatchState *ms, const char *s, const char *p, const char *ep) {
    if (s >= ms->src_end)
        return 0;
    else {
        utfint ch = 0, pch = 0;
        luU_decodechecked(ms->L, s, &ch);
        p = luU_decodechecked(ms->L, p, &pch);
        switch (pch) {
        case '.': return 1; /* matches any char */
        case LU_ESC:
            luU_decodechecked(ms->L, p, &pch);
            return luM_class(ch, pch);
        case '[': return luM_bracketclass(ms, ch, p - 1, ep - 1);
        default: return pch == ch;
        }
    }
}

static const char *luM_balance(
        lu_MatchState *ms, const char *s, const char **p) {
    utfint ch = 0, begin = 0, end = 0;
    *p = luU_decodechecked(ms->L, *p, &begin);
    if (*p >= ms->p_end)
        luaL_error(
                ms->L,
                "malformed pattern "
                "(missing arguments to " LU_QL("%%b") ")");
    *p = luU_decodechecked(ms->L, *p, &end);
    s = luU_decodechecked(ms->L, s, &ch);
    if (ch != begin)
        return NULL;
    else {
        int cont = 1;
        while (s < ms->src_end) {
            s = luU_decodechecked(ms->L, s, &ch);
            if (ch == end) {
                if (--cont == 0) return s;
            } else if (ch == begin)
                cont++;
        }
    }
    return NULL; /* string ends out of balance */
}

static const char *luM_maxexpand(
        lu_MatchState *ms, const char *s, const char *p, const char *ep) {
    const char *m = s; /* matched end of single match p */
    while (luM_single(ms, m, p, ep)) m = luU_next(m, ms->src_end);
    /* keeps trying to match with the maximum repetitions */
    while (s <= m) {
        const char *res = luM_match(ms, m, ep + 1);
        if (res) return res;
        /* else didn't match; reduce 1 repetition to try again */
        if (s == m) break;
        m = luU_prev(s, m);
    }
    return NULL;
}

static const char *luM_minexpand(
        lu_MatchState *ms, const char *s, const char *p, const char *ep) {
    for (;;) {
        const char *res = luM_match(ms, s, ep + 1);
        if (res != NULL)
            return res;
        else if (luM_single(ms, s, p, ep))
            s = luU_next(s, ms->src_end); /* try with one more repetition */
        else
            return NULL;
    }
}

static const char *luM_startcapture(
        lu_MatchState *ms, const char *s, const char *p, int what) {
    const char *res;
    int         level = ms->level;
    if (level >= LU_MAXCAPTURES) luaL_error(ms->L, "too many captures");
    ms->capture[level].init = s;
    ms->capture[level].len = what;
    ms->level = level + 1;
    if ((res = luM_match(ms, s, p)) == NULL) /* match failed? */
        ms->level--;                         /* undo capture */
    return res;
}

static const char *luM_endcapture(
        lu_MatchState *ms, const char *s, const char *p) {
    int         l = luM_toclosecapture(ms);
    const char *res;
    ms->capture[l].len = s - ms->capture[l].init; /* close capture */
    if ((res = luM_match(ms, s, p)) == NULL)      /* match failed? */
        ms->capture[l].len = LU_CAP_UNFINISHED;   /* undo capture */
    return res;
}

static const char *luM_capture(lu_MatchState *ms, const char *s, int l) {
    size_t len;
    l = luM_checkcapture(ms, l);
    len = ms->capture[l].len;
    if ((size_t)(ms->src_end - s) >= len
        && memcmp(ms->capture[l].init, s, len) == 0)
        return s + len;
    else
        return NULL;
}

#define LU_OK   0
#define LU_FAIL (-1)
#define LU_INIT 1
#define LU_DFLT 2

/* Handle plain pattern elements; returns a MatchResult. */
static int luM_basic(
        lu_MatchState *ms, const char *s, const char *p, utfint ch,
        const char **ps) {
    assert(ch == '(' || ch == ')' || ch == '$');
    switch (ch) {
    case '(':
        if (*(p + 1) == ')') /* position capture? */
            *ps = luM_startcapture(ms, s, p + 2, LU_CAP_POSITION);
        else
            *ps = luM_startcapture(ms, s, p + 1, LU_CAP_UNFINISHED);
        return LU_OK;
    case ')': *ps = luM_endcapture(ms, s, p + 1); return LU_OK;
    case '$':
        if ((p + 1) != ms->p_end) return LU_DFLT;
        *ps = (s == ms->src_end) ? s : NULL;
    default: return LU_OK;
    }
}

static int luM_escapedbalance(
        lu_MatchState *ms, const char *s, const char *p, const char **ps,
        const char **pp) {
    s = luM_balance(ms, s, &p);
    if (s != NULL) return (*ps = s, *pp = p), LU_INIT;
    return (*ps = NULL), LU_FAIL;
}

static int luM_escapedfrontier(
        lu_MatchState *ms, const char *s, const char *p, const char **ps,
        const char **pp) {
    const char *ep;
    utfint      previous = 0, current = 0;
    if (*p != '[') luaL_error(ms->L, "missing '[' after '%%f' in pattern");
    ep = luM_classend(ms, p);
    if (s != ms->src_init) luU_decode(luU_prev(ms->src_init, s), &previous, 0);
    if (s != ms->src_end) luU_decode(s, &current, 0);
    if (!luM_bracketclass(ms, previous, p, ep - 1)
        && luM_bracketclass(ms, current, p, ep - 1)) {
        *ps = s;
        *pp = ep;
        return LU_INIT;
    }
    *ps = NULL;
    return LU_FAIL;
}

static int luM_escapeddigit(
        lu_MatchState *ms, const char *s, const char *p, utfint ch,
        const char **ps, const char **pp) {
    const char *res = luM_capture(ms, s, ch);
    if (res != NULL) {
        *ps = res;
        *pp = p;
        return LU_INIT;
    }
    *ps = NULL;
    return LU_FAIL;
}

/* Handle an escaped pattern element after '%'; returns a MatchResult. */
static int luM_escaped(
        lu_MatchState *ms, const char *s, const char *p, const char *prev_p,
        utfint ch, const char **ps, const char **pp) {
    if (ch == 'b') return luM_escapedbalance(ms, s, p, ps, pp);
    if (ch == 'f') return luM_escapedfrontier(ms, s, p, ps, pp);
    if (ch >= '0' && ch <= '9') return luM_escapeddigit(ms, s, p, ch, ps, pp);
    *pp = prev_p;
    return LU_DFLT;
}

static int luM_suffix(
        lu_MatchState *ms, const char *s, const char *p, const char *ep,
        const char *next_s, const char **ps, const char **pp) {
    const char *res, *next_ep;
    switch (*ep) {
    case '?':
        next_ep = luU_next(ep, ms->p_end);
        if ((res = luM_match(ms, next_s, next_ep)) != NULL)
            return (*ps = res, *pp = p), LU_OK;
        return (*pp = next_ep), LU_INIT;
    case '+':
    case '*':
        *ps = luM_maxexpand(ms, (*ep == '+') ? next_s : s, p, ep), *pp = p;
        return LU_OK;
    case '-': *ps = luM_minexpand(ms, s, p, ep), *pp = p; return LU_OK;
    default: *ps = next_s, *pp = ep; return LU_INIT;
    }
}

/* Handle the default pattern-class suffix; returns a MatchResult. */
static int luM_default(
        lu_MatchState *ms, const char *s, const char *p, const char **ps,
        const char **pp) {
    const char *ep = luM_classend(ms, p);
    const char *next_s;
    if (!luM_single(ms, s, p, ep)) {
        if (*ep == '*' || *ep == '?' || *ep == '-') {
            *pp = ep + 1;
            return LU_INIT;
        }
        *ps = NULL;
        return LU_FAIL;
    }
    next_s = luU_next(s, ms->src_end);
    return luM_suffix(ms, s, p, ep, next_s, ps, pp);
}

/* Execute one matching step; never returns LU_DFLT to the caller. */
static int luM_step(
        lu_MatchState *ms, const char *s, const char *p, utfint ch,
        const char **ps, const char **pp) {
    const char *prev_p;
    utfint      esc_ch;
    int         r;
    switch (ch) {
    case '(':
    case ')':
    case '$':
        r = luM_basic(ms, s, p, ch, ps);
        if (r == LU_DFLT) return luM_default(ms, s, p, ps, pp);
        return r;
    case LU_ESC:
        prev_p = p;
        p = luU_decodechecked(ms->L, p + 1, &esc_ch);
        r = luM_escaped(ms, s, p, prev_p, esc_ch, ps, pp);
        if (r == LU_DFLT) return luM_default(ms, s, prev_p, ps, pp);
        return r;
    default: return luM_default(ms, s, p, ps, pp);
    }
}

static const char *luM_match(lu_MatchState *ms, const char *s, const char *p) {
    if (ms->matchdepth-- == 0) luaL_error(ms->L, "pattern too complex");
init:                     /* using goto's to optimize tail recursion */
    if (p != ms->p_end) { /* end of pattern? */
        utfint ch = 0;
        int    r;
        luU_decodechecked(ms->L, p, &ch);
        r = luM_step(ms, s, p, ch, &s, &p);
        if (r == LU_INIT) goto init;
        if (r == LU_FAIL) s = NULL;
    }
    ms->matchdepth++;
    return s;
}

static const char *luM_memfind(
        const char *s1, size_t l1, const char *s2, size_t l2) {
    if (l2 == 0)
        return s1; /* empty strings are everywhere */
    else if (l2 > l1)
        return NULL; /* avoids a negative `l1' */
    else {
        const char *init; /* to search for a `*s2' inside `s1' */
        l2--;             /* 1st char will be checked by `memchr' */
        l1 = l1 - l2;     /* `s2' cannot be found after that */
        while (l1 > 0 && (init = (const char *)memchr(s1, *s2, l1)) != NULL) {
            init++; /* 1st char is already checked */
            if (memcmp(init, s2 + 1, l2) == 0)
                return init - 1;
            else { /* correct `l1' and `s1' to try again */
                l1 -= init - s1;
                s1 = init;
            }
        }
        return NULL; /* not found */
    }
}

static int luM_getindex(const char *p, lu_Slice s) {
    int idx;
    for (idx = 0; s.s < s.e && s.s < p; ++idx) s.s = luU_next(s.s, s.e);
    return s.s == p ? idx : idx - 1;
}

static void luM_pushone(lu_MatchState *ms, int i, lu_Slice s) {
    if (i >= ms->level) {
        if (i == 0)                                 /* ms->level == 0, too */
            lua_pushlstring(ms->L, s.s, s.e - s.s); /* add whole match */
        else
            luaL_error(ms->L, "invalid capture index");
    } else {
        ptrdiff_t l = ms->capture[i].len;
        if (l == LU_CAP_UNFINISHED) luaL_error(ms->L, "unfinished capture");
        if (l == LU_CAP_POSITION) {
            int idx = luM_getindex(
                    ms->capture[i].init,
                    lu_newslice(ms->src_init, ms->src_end - ms->src_init));
            lua_pushinteger(ms->L, idx + 1);
        } else
            lua_pushlstring(ms->L, ms->capture[i].init, l);
    }
}

static int luM_pushcaptures(lu_MatchState *ms, lu_Slice s) {
    int i;
    int nlevels = (ms->level == 0 && s.s) ? 1 : ms->level;
    luaL_checkstack(ms->L, nlevels, "too many captures");
    for (i = 0; i < nlevels; i++) luM_pushone(ms, i, s);
    return nlevels; /* number of strings pushed */
}

/* check whether pattern has no special characters */
static int luM_nospecials(const char *p, const char *ep) {
    while (p < ep) {
        if (strpbrk(p, LU_SPECIALS)) return 0;
        p += strlen(p) + 1; /* may have more after \0 */
    }
    return 1; /* no special chars found */
}

/* utf8 pattern matching interface */

static int luM_findplain(lu_MatchState *ms, lu_Slice cur, lua_Integer idx) {
    const char *s = ms->src_init, *es = ms->src_end;
    const char *p = ms->p, *ep = ms->p_end;
    const char *s2, *e2;
    s2 = luM_memfind(cur.s, cur.e - cur.s, p, ep - p);
    if (s2) {
        e2 = s2 + (ep - p);
        if (lu_iscontp(e2)) e2 = luU_next(e2, es);
        lua_pushinteger(
                ms->L, idx = luM_getindex(s2, lu_newslice(s, es - s)) + 1);
        lua_pushinteger(
                ms->L, idx + luM_getindex(e2, lu_newslice(s2, es - s2)) - 1);
        return 2;
    }
    return 0;
}

static int luM_findat(
        lua_State *L, lu_MatchState *ms, const char *p, const char *init,
        lua_Integer idx, int find) {
    const char *res;
    ms->level = 0;
    assert(ms->matchdepth == LU_MAXCCALLS);
    if ((res = luM_match(ms, init, p)) != NULL) {
        if (find) {
            lua_pushinteger(L, idx); /* start */
            lua_pushinteger(
                    L, idx + luU_length(lu_newslice(init, res - init))
                               - 1); /* end */
            return luM_pushcaptures(ms, (lu_Slice){NULL, NULL}) + 2;
        } else
            return luM_pushcaptures(ms, lu_newslice(init, res - init));
    }
    return 0;
}

static int luM_findpattern(
        lu_MatchState *ms, lu_Slice cur, lua_Integer idx, int f) {
    const char *s = ms->src_init, *es = ms->src_end, *p = ms->p;
    const char *init = cur.s;
    int         anchor = (*p == '^');
    int         n;
    if (anchor) p++; /* skip anchor character */
    if (idx < 0)
        idx += luU_length(lu_newslice(s, es - s)) + 1; /* TODO not very good */
    ms->matchdepth = LU_MAXCCALLS;
    do {
        n = luM_findat(ms->L, ms, p, init, idx, f);
        if (n) return n;
        if (init == es) break;
        idx += 1;
        init = luU_next(init, es);
    } while (init <= es && !anchor);
    return 0;
}

static int luM_find(lua_State *L, int find) {
    lu_Slice      sl = lu_checkslice(L, 1);
    const char   *s = sl.s, *es = sl.e;
    lu_Slice      pl = lu_checkslice(L, 2);
    const char   *p = pl.s, *ep = pl.e;
    lua_Integer   idx = luaL_optinteger(L, 3, 1);
    lu_MatchState ms;
    const char   *init;
    int           n;
    if (!idx) idx = 1;
    init = luU_relat(lu_newslice(s, es - s), (int)idx);
    if (init == NULL) {
        if (idx > 0) return lua_pushnil(L), 1;
        init = s;
    }
    ms.L = L;
    ms.matchdepth = LU_MAXCCALLS;
    ms.src_init = s;
    ms.src_end = es;
    ms.p = p;
    ms.p_end = ep;
    /* explicit request or no special characters? */
    if (find && (lua_toboolean(L, 4) || luM_nospecials(p, ep)))
        n = luM_findplain(&ms, lu_newslice(init, es - init), idx);
    else
        n = luM_findpattern(&ms, lu_newslice(init, es - init), idx, find);
    if (n) return n;
    return lua_pushnil(L), 1; /* not found */
}

static int Lutf8_find(lua_State *L) { return luM_find(L, 1); }
static int Lutf8_match(lua_State *L) { return luM_find(L, 0); }

static int luM_gmatch(lua_State *L) {
    lu_MatchState ms;
    lu_Slice      sl = lu_checkslice(L, lua_upvalueindex(1));
    lu_Slice      pl = lu_checkslice(L, lua_upvalueindex(2));
    const char   *s = sl.s, *es = sl.e, *p = pl.s, *ep = pl.e;
    lua_Integer   pos = lua_tointeger(L, lua_upvalueindex(3));
    lua_Integer   last = lua_tointeger(L, lua_upvalueindex(4));
    const char   *src;
    ms.L = L;
    ms.matchdepth = LU_MAXCCALLS;
    ms.src_init = s;
    ms.src_end = es;
    ms.p_end = ep;
    for (src = s + pos; src <= es;) {
        const char *e;
        ms.level = 0;
        assert(ms.matchdepth == LU_MAXCCALLS);
        if ((e = luM_match(&ms, src, p)) != NULL && e - s != last) {
            lua_pushinteger(L, e - s);
            lua_replace(L, lua_upvalueindex(3));
            lua_pushinteger(L, e - s);
            lua_replace(L, lua_upvalueindex(4));
            return luM_pushcaptures(&ms, lu_newslice(src, e - src));
        }
        if (src == es) break;
        src = luU_next(src, es);
    }
    return 0; /* not found */
}

static int Lutf8_gmatch(lua_State *L) {
    luaL_checkstring(L, 1);
    luaL_checkstring(L, 2);
    lua_settop(L, 2);
    lua_pushinteger(L, 0);  /* current position */
    lua_pushinteger(L, -1); /* last match end */
    return lua_pushcclosure(L, luM_gmatch, 4), 1;
}

static void luM_adds(lu_MatchState *ms, luaL_Buffer *b, lu_Slice s) {
    lu_Slice    newsl = lu_toslice(ms->L, 3);
    const char *news = newsl.s, *new_end = newsl.e;
    while (news < new_end) {
        utfint ch = 0;
        news = luU_decodechecked(ms->L, news, &ch);
        if (ch != LU_ESC)
            luL_addutf8char(b, ch);
        else {
            news = luU_decodechecked(ms->L, news, &ch); /* skip ESC */
            if (!luT_isdigit(ch)) {
                if (ch != LU_ESC)
                    luaL_error(
                            ms->L,
                            "invalid use of " LU_QL(
                                    "%c") " in replacement string",
                            LU_ESC);
                luL_addutf8char(b, ch);
            } else if (ch == '0')
                luaL_addlstring(b, s.s, s.e - s.s);
            else {
                luM_pushone(ms, ch - '1', s);
                luaL_addvalue(b); /* add capture to accumulated result */
            }
        }
    }
}

static int luM_addvalue(lu_MatchState *ms, luaL_Buffer *b, lu_Slice s, int tr) {
    lua_State *L = ms->L;
    int        n;
    switch (tr) {
    case LUA_TFUNCTION:
        lua_pushvalue(L, 3);
        n = luM_pushcaptures(ms, s);
        lua_call(L, n, 1);
        break;
    case LUA_TTABLE:
        luM_pushone(ms, 0, s);
        lua_gettable(L, 3);
        break;
    default: /* LUA_TNUMBER or LUA_TSTRING */ return luM_adds(ms, b, s), 1;
    }
    if (!lua_toboolean(L, -1)) { /* nil or false? */
        lua_pop(L, 1);
        return luaL_addlstring(b, s.s, s.e - s.s), 0; /* keep original text */
    } else if (!lua_isstring(L, -1))
        return luaL_error(
                L, "invalid replacement value (a %s)", luaL_typename(L, -1));
    return luaL_addvalue(b), 1; /* add result to accumulator */
}

/* Try one gsub step; returns 0 when the end of string is reached. */
static int luM_onematch(lu_MatchState *ms, luaL_Buffer *b, lu_Slice *src) {
    const char  *s = src->s, *es = src->e, *p = ms->p;
    const char  *e;
    utfint       ch;
    int          tr = ms->tr;
    lua_Integer *pn = ms->pn;
    ms->level = 0;
    assert(ms->matchdepth == LU_MAXCCALLS);
    e = luM_match(ms, s, p);
    if (e && e != ms->lastmatch) {
        (*pn)++;
        ms->changed = luM_addvalue(ms, b, lu_newslice(s, e - s), tr)
                   || ms->changed;
        src->s = e;
        ms->lastmatch = e;
    } else if (s < es) {
        s = luU_decodechecked(ms->L, s, &ch);
        luL_addutf8char(b, ch);
        src->s = s;
    } else
        return 0;
    return 1;
}

static int Lutf8_gsub(lua_State *L) {
    lu_Slice      sl = lu_checkslice(L, 1);
    const char   *s = sl.s, *es = sl.e;
    lu_Slice      pl = lu_checkslice(L, 2);
    const char   *p = pl.s, *ep = pl.e;
    int           tr = lua_type(L, 3);
    lua_Integer   max_s = luaL_optinteger(L, 4, (es - s) + 1);
    int           anchor = (*p == '^');
    lua_Integer   n = 0;
    lu_MatchState ms;
    luaL_Buffer   b;
    luaL_argcheck(
            L,
            tr == LUA_TNUMBER || tr == LUA_TSTRING || tr == LUA_TFUNCTION
                    || tr == LUA_TTABLE,
            3, "string/function/table expected");
    luaL_buffinit(L, &b);
    if (anchor) p++; /* skip anchor character */
    ms.L = L;
    ms.matchdepth = LU_MAXCCALLS;
    ms.src_init = s;
    ms.src_end = es;
    ms.p = p;
    ms.p_end = ep;
    ms.tr = tr;
    ms.pn = &n;
    ms.lastmatch = NULL;
    ms.changed = 0;
    while (n < max_s) {
        if (!luM_onematch(&ms, &b, &sl)) break;
        if (anchor) break;
    }
    if (!ms.changed)
        lua_pushvalue(L, 1); /* return original string */
    else {
        luaL_addlstring(&b, sl.s, es - sl.s);
        luaL_pushresult(&b);
    }
    lua_pushinteger(L, n); /* number of substitutions */
    return 2;
}

static int Lutf8_isvalid(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    const char *invalid = luU_invalidoffset(lu_newslice(s, e - s));
    return lua_pushboolean(L, invalid == NULL), 1;
}

static int Lutf8_invalidoffset(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;
    const char *orig_s = s;
    lua_Integer offset = luaL_optinteger(L, 2, 0);
    if (offset > 1) {
        offset -= 1;
        if ((s += offset) >= e) return lua_pushnil(L), 1;
    } else if (offset < 0 && s - e < offset)
        s = e + offset;
    const char *invalid = luU_invalidoffset(lu_newslice(s, e - s));
    if (invalid == NULL) return lua_pushnil(L), 1;
    return lua_pushinteger(L, invalid - orig_s + 1), 1;
}

/* Step past one contiguous run of invalid bytes; update *ps and *pinvalid */
static void luU_skipinvalid(lu_Slice *s, const char **pinvalid) {
    const char *e = s->e, *invalid = *pinvalid;
    s->s = invalid;
    while (s->s == invalid)
        s->s++, invalid = luU_invalidoffset(lu_newslice(s->s, e - s->s));
    *pinvalid = invalid;
}

static int luU_cleanreplace(lua_State *L, lu_Slice s, lu_Slice r) {
    const char *invalid = luU_invalidoffset(s);
    const char *e = s.e;
    luaL_Buffer buff;
    luaL_buffinit(L, &buff);
    while (1) {
        /* Invariant: 's' points to first GOOD byte not in output buffer,
         * 'invalid' points to first BAD byte after that */
        luaL_addlstring(&buff, s.s, invalid - s.s);
        luaL_addlstring(&buff, r.s, r.e - r.s);
        /* Replace a contiguous run of bad bytes with a single replacement. */
        luU_skipinvalid(&s, &invalid);
        if (invalid == NULL) {
            luaL_addlstring(&buff, s.s, e - s.s);
            /* String was not clean */
            return luaL_pushresult(&buff), lua_pushboolean(L, 0), 2;
        }
    }
}

static int Lutf8_clean(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *s = sl.s, *e = sl.e;

    /* Default replacement string is REPLACEMENT CHARACTER U+FFFD */
    size_t      repl_len;
    const char *r = luaL_optlstring(L, 2, "\xEF\xBF\xBD", &repl_len);

    if (lua_gettop(L) > 1
        && luU_invalidoffset(lu_newslice(r, repl_len)) != NULL)
        /* Check if replacement string is valid UTF-8 or not */
        luaL_error(L, "replacement string must be valid UTF-8");

    if (luU_invalidoffset(lu_newslice(s, e - s)) == NULL)
        /* Return input string without modification */
        /* String was clean already */
        return lua_settop(L, 1), lua_pushboolean(L, 1), 2;
    return luU_cleanreplace(L, lu_newslice(s, e - s), lu_newslice(r, repl_len));
}

/* Return 0 if this codepoint makes the string not NFC */
static int luN_checkcp(
        utfint ch, nfc_table *entry, utfint starter, int cc, int prevcc) {
    if (cc && cc < prevcc) return 0;
    if (entry && !luC_check(ch, entry, starter, cc, prevcc)) return 0;
    return 1;
}

/* Scan from 's' to 'e'; return 1 if already NFC, else 0 and set *starter_p */
static int luN_scan(lua_State *L, lu_Slice *v, utfint *st, int *pc) {
    const char *np, *p = v->s, *e = v->e;
    utfint      ch;
    int         cc;
    for (; p < e; p = np) {
        np = luU_decode(p, &ch, 1);
        luaL_argcheck(L, (np != NULL), 1, "string is not valid UTF-8");
        cc = luN_findcanon(ch);
        if (!luN_checkcp(ch, luN_quickcheck(ch), *st, cc, *pc)) return 0;
        if (!(*pc = cc)) *st = ch, v->s = p;
    }
    return 1;
}

static int Lutf8_isnfc(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    const char *e = sl.e, *s = sl.s;
    utfint      starter = 0, ch;
    int         prevcc = 0, cc;
    while (s < e) {
        s = luU_decode(s, &ch, 1);
        luaL_argcheck(L, (s != NULL), 1, "string is not valid UTF-8");
        if (ch < 0x300) {
            starter = ch, prevcc = 0; /* Fast path */
            continue;
        }
        cc = luN_findcanon(ch);
        if (!luN_checkcp(ch, luN_quickcheck(ch), starter, cc, prevcc))
            return lua_pushboolean(L, 0), 1;
        prevcc = cc;
        if (!cc) starter = ch;
    }
    return lua_pushboolean(L, 1), 1;
}

static int Lutf8_normalize_nfc(lua_State *L) {
    lu_Slice    sl = lu_checkslice(L, 1);
    lu_Slice    scan = sl;
    const char *e = sl.e, *s = sl.s;
    utfint      starter = 0;
    int         prevcc = 0;
    luaL_Buffer buff;

    /* First scan to see if we can find any problems... if not, we may just
     * return the input string unchanged */
    if (luN_scan(L, &scan, &starter, &prevcc))
        return lua_settop(L, 1), lua_pushboolean(L, 1), 2;

    /* We will need to build a new string, this one is not NFC */
    luaL_buffinit(L, &buff);
    luaL_addlstring(&buff, s, scan.s - s);
    luN_fromstring(L, &buff, lu_newslice(scan.s, e - scan.s));
    return luaL_pushresult(&buff), lua_pushboolean(L, 0), 2;
}

typedef enum lu_GraphemeState {
    GS_NO,
    GS_BIND,
    GS_BREAK,
    GS_CONTINUE
} lu_GraphemeState;

typedef struct lu_GraphemeCtx {
    lua_State  *L;
    const char *s, *e, *p, *next_p;
    utfint      ch, next_ch;
} lu_GraphemeCtx;

static int luG_ctrl(lu_GraphemeCtx *ctx) {
    if (ctx->ch == '\r') {
        if (ctx->next_ch == '\n') return GS_BIND;
        return GS_BREAK;
    }
    if (ctx->ch == '\n' || ctx->next_ch == '\r' || ctx->next_ch == '\n')
        return GS_BREAK;
    if (luT_find(cntrl_table, lu_tabsize(cntrl_table), ctx->ch)
        && !luT_find(prepend_table, lu_tabsize(prepend_table), ctx->ch)
        && ctx->ch != 0x200D
        && !luT_find(compose_table, lu_tabsize(compose_table), ctx->ch))
        return GS_BREAK;
    if (luT_find(cntrl_table, lu_tabsize(cntrl_table), ctx->next_ch)
        && !luT_find(prepend_table, lu_tabsize(prepend_table), ctx->next_ch)
        && !luT_find(compose_table, lu_tabsize(compose_table), ctx->next_ch))
        return GS_BREAK;
    return GS_NO;
}

static int luG_zwj(lu_GraphemeCtx *ctx) {
    utfint      nextnext_ch;
    const char *probe_ep;
    if (ctx->next_ch != 0x200D) return GS_NO;
    if (ctx->next_p < ctx->e
        && luT_find(
                pictographic_table, lu_tabsize(pictographic_table), ctx->ch)) {
        probe_ep = luU_decodechecked(ctx->L, ctx->next_p, &nextnext_ch);
        if (luT_find(
                    pictographic_table, lu_tabsize(pictographic_table),
                    nextnext_ch)) {
            ctx->p = probe_ep;
            ctx->ch = nextnext_ch;
            return GS_CONTINUE;
        }
    }
    return GS_BIND;
}

static int luG_indic(lu_GraphemeCtx *ctx) {
    utfint      probed_ch;
    const char *probe;
    int         indic_type, saw_linker;
    if (luG_indictype(ctx->ch) != INDIC_CONSONANT) return GS_NO;
    probed_ch = ctx->next_ch;
    probe = ctx->next_p;
    indic_type = luG_indictype(probed_ch);
    saw_linker = 0;
    while (indic_type) {
        if (indic_type == INDIC_LINKER) {
            saw_linker = 1;
        } else if (indic_type == INDIC_CONSONANT) {
            if (!saw_linker) break;
            ctx->p = probe;
            ctx->ch = probed_ch;
            return GS_CONTINUE;
        }
        if (probe >= ctx->e) break;
        probe = luU_decodechecked(ctx->L, probe, &probed_ch);
        indic_type = luG_indictype(probed_ch);
    }
    return GS_NO;
}

/* Consume extend/ZWJ/pictographic runs after an Extended_Pictographic. */
static void luG_extendscan(lu_GraphemeCtx *ctx) {
    utfint      probed_ch;
    const char *probe = ctx->next_p;
    while (probe < ctx->e) {
        probe = luU_decodechecked(ctx->L, probe, &probed_ch);
        if (probed_ch == 0x200D) {
            if (probe < ctx->e) {
                probe = luU_decodechecked(ctx->L, probe, &probed_ch);
                if (luT_find(
                            pictographic_table, lu_tabsize(pictographic_table),
                            probed_ch)) {
                    ctx->next_p = probe;
                    ctx->next_ch = probed_ch;
                }
            }
            break;
        } else if (
                luT_find(compose_table, lu_tabsize(compose_table), probed_ch)
                || (probed_ch >= 0x1F3FB && probed_ch <= 0x1F3FF)) {
            ctx->next_p = probe;
            ctx->next_ch = probed_ch;
        } else {
            break;
        }
    }
}

static int luG_hangul(lu_GraphemeCtx *ctx) {
    int hangul1 = luG_hangultype(ctx->ch);
    int hangul2;
    if (!hangul1) return GS_NO;
    hangul2 = luG_hangultype(ctx->next_ch);
    if (!hangul2) return GS_NO;
    if (hangul1 == HANGUL_L) return (hangul2 != HANGUL_T) ? GS_BIND : GS_NO;
    if (hangul1 == HANGUL_LV || hangul1 == HANGUL_V)
        return (hangul2 == HANGUL_V || hangul2 == HANGUL_T) ? GS_BIND : GS_NO;
    if (hangul1 == HANGUL_LVT || hangul1 == HANGUL_T)
        return (hangul2 == HANGUL_T) ? GS_BIND : GS_NO;
    return GS_NO;
}

static int luG_extend(lu_GraphemeCtx *ctx) {
    if (luT_find(compose_table, lu_tabsize(compose_table), ctx->next_ch)
        || (ctx->next_ch >= 0x1F3FB && ctx->next_ch <= 0x1F3FF)) {
        if (ctx->next_p < ctx->e
            && luT_find(
                    pictographic_table, lu_tabsize(pictographic_table),
                    ctx->ch))
            luG_extendscan(ctx);
        return GS_BIND;
    }
    if (luT_find(
                spacing_mark_table, lu_tabsize(spacing_mark_table),
                ctx->next_ch))
        return GS_BIND;
    if (luT_find(prepend_table, lu_tabsize(prepend_table), ctx->ch))
        return GS_BIND;
    if (ctx->ch >= 0x1F1E6 && ctx->ch <= 0x1F1FF && ctx->next_ch >= 0x1F1E6
        && ctx->next_ch <= 0x1F1FF) {
        ctx->p = ctx->next_p;
        ctx->ch = 0xFFFE;
        return GS_CONTINUE;
    }
    return luG_hangul(ctx);
}

static void luG_next(lu_GraphemeCtx *ctx) {
    int r;
    while (1) {
        ctx->next_p = luU_decodechecked(ctx->L, ctx->p, &ctx->next_ch);
        r = luG_ctrl(ctx);
        if (!r) r = luG_zwj(ctx);
        if (!r) r = luG_indic(ctx);
        if (!r) r = luG_extend(ctx);
        if (r == GS_BREAK || r == GS_NO) return;
        if (r == GS_CONTINUE) continue;
        ctx->p = ctx->next_p;
        ctx->ch = ctx->next_ch;
    }
}

static int luG_iter(lua_State *L) {
    const char    *s = luaL_checkstring(L, lua_upvalueindex(1));
    lua_Integer    pos = luaL_checkinteger(L, lua_upvalueindex(2));
    lua_Integer    end = luaL_checkinteger(L, lua_upvalueindex(3));
    lu_GraphemeCtx ctx;
    if (pos > end) return lua_pushnil(L), 1;
    ctx.L = L;
    ctx.s = s;
    ctx.e = s + end;
    ctx.p = luU_decodechecked(L, s + pos - 1, &ctx.ch);
    luG_next(&ctx);
    lua_pushinteger(L, (ctx.p - s) + 1);
    lua_replace(L, lua_upvalueindex(2));
    return lua_pushinteger(L, pos), lua_pushinteger(L, ctx.p - s), 2;
}

static int Lutf8_grapheme_indices(lua_State *L) {
    size_t      len;
    lua_Integer start, end;
    luaL_checklstring(L, 1, &len);
    start = luB_relat(luaL_optinteger(L, 2, 1), len);
    end = luB_relat(luaL_optinteger(L, 3, len), len);
    luaL_argcheck(L, start >= 1, 2, "out of range");
    luaL_argcheck(L, end <= (lua_Integer)len, 3, "out of range");

    lua_settop(L, 1);
    lua_pushinteger(L, start);
    lua_pushinteger(L, end);
    return lua_pushcclosure(L, luG_iter, 3), 1;
}

/* lua module import interface */

#if LUA_VERSION_NUM >= 502
static const char LU_UTF8PATT[] = "[\0-\x7F\xC2-\xF4][\x80-\xBF]*";
#else
static const char LU_UTF8PATT[] = "[%z\1-\x7F\xC2-\xF4][\x80-\xBF]*";
#endif

LUALIB_API int luaopen_utf8(lua_State *L) {
    luaL_Reg utf8libs[] = {
#define ENTRY(name) {#name, Lutf8_##name}
            ENTRY(offset),  ENTRY(codes),         ENTRY(codepoint),

            ENTRY(find),    ENTRY(gmatch),        ENTRY(gsub),
            ENTRY(match),   ENTRY(len),           ENTRY(sub),
            ENTRY(reverse), ENTRY(lower),         ENTRY(upper),
            ENTRY(byte),    ENTRY(char),

            ENTRY(title),   ENTRY(fold),          ENTRY(escape),
            ENTRY(insert),  ENTRY(remove),        ENTRY(charpos),
            ENTRY(next),    ENTRY(ncasecmp),

            ENTRY(width),   ENTRY(widthindex),    ENTRY(widthlimit),

            ENTRY(isvalid), ENTRY(invalidoffset), ENTRY(clean),
            ENTRY(isnfc),   ENTRY(normalize_nfc), ENTRY(grapheme_indices),
#undef ENTRY
            {NULL, NULL}};

#if LUA_VERSION_NUM >= 502
    luaL_newlib(L, utf8libs);
#else
    luaL_register(L, "utf8", utf8libs);
#endif

    lua_pushlstring(L, LU_UTF8PATT, sizeof(LU_UTF8PATT) - 1);
    lua_setfield(L, -2, "charpattern");

    lua_pushliteral(L, LU_VERSION);
    lua_setfield(L, -2, "version");
    return 1;
}

/* win32cc: flags+='-Wall -Wextra -s -O2 -mdll -DLUA_BUILD_AS_DLL'
 * win32cc: libs+='-llua54.dll' output='lua-utf8.dll'
 * win32cc: run='lua.exe test.lua'
 * maccc: run='lua -- test_compat.lua'
 * maccc: flags+='-g --coverage -bundle -undefined dynamic_lookup'
 * output='lua-utf8.so' */
