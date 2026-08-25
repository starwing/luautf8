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

#define LUTF8_VERSION "0.2.1"

#define UTF8_BUFFSZ    8
#define UTF8_MAX       0x7FFFFFFFu
#define UTF8_MAXCP     0x10FFFFu
#define iscontp(p)     ((*(p) & 0xC0) == 0x80)
#define CAST(tp, expr) ((tp)(expr))

typedef struct lu_Slice {
    const char *s, *e;
} lu_Slice;

static inline lu_Slice lu_newslice(const char *s, size_t len) {
    assert(s != NULL);
    lu_Slice slice = {s, s + len};
    return slice;
}

#ifndef LUA_QL
# define LUA_QL(x) "'" x "'"
#endif

static int utf8_invalid(utfint ch) {
    return (ch > UTF8_MAXCP || (0xD800u <= ch && ch <= 0xDFFFu));
}

static size_t utf8_encode(char *buff, utfint x) {
    int n = 1; /* number of bytes put in buffer (backwards) */
    assert(x <= UTF8_MAX);
    if (x < 0x80) /* ascii? */
        buff[UTF8_BUFFSZ - 1] = x & 0x7F;
    else {                 /* need continuation bytes */
        utfint mfb = 0x3f; /* maximum that fits in first byte */
        do {               /* add continuation bytes */
            buff[UTF8_BUFFSZ - (n++)] = 0x80 | (x & 0x3f);
            x >>= 6;   /* remove added bits */
            mfb >>= 1; /* now there is one less bit available in first byte */
        } while (x > mfb); /* still needs continuation byte? */
        buff[UTF8_BUFFSZ - n] = ((~mfb << 1) | x) & 0xFF; /* add first byte */
    }
    return n;
}

static const char *utf8_decode(const char *s, utfint *val, int strict) {
    static const utfint limits[] = {~0u,      0x80u,     0x800u,
                                    0x10000u, 0x200000u, 0x4000000u};
    unsigned int        c = (unsigned char)s[0];
    utfint              res = 0; /* final result */
    if (c < 0x80)                /* ascii? */
        res = c;
    else {
        int count = 0;              /* to count number of continuation bytes */
        for (; c & 0x40; c <<= 1) { /* while it needs continuation bytes... */
            unsigned int cc = (unsigned char)s[++count]; /* read next byte */
            if ((cc & 0xC0) != 0x80) /* not a continuation byte? */
                return NULL;         /* invalid byte sequence */
            res = (res << 6)
                | (cc & 0x3F); /* add lower 6 bits from cont. byte */
        }
        res |= ((utfint)(c & 0x7F) << (count * 5)); /* add first byte */
        if (count > 5 || res > UTF8_MAX || res < limits[count])
            return NULL; /* invalid byte sequence */
        s += count;      /* skip continuation bytes read */
    }
    if (strict) {
        /* check for invalid code points; too large or surrogates */
        if (res > UTF8_MAXCP || (0xD800u <= res && res <= 0xDFFFu)) return NULL;
    }
    if (val) *val = res;
    return s + 1; /* +1 to include first byte */
}

static const char *utf8_prev(const char *s, const char *e) {
    while (s < e && iscontp(e - 1)) --e;
    return s < e ? e - 1 : s;
}

static const char *utf8_next(const char *s, const char *e) {
    while (s < e && iscontp(s + 1)) ++s;
    return s < e ? s + 1 : e;
}

static size_t utf8_length(lu_Slice s) {
    size_t i;
    for (i = 0; s.s < s.e; ++i) s.s = utf8_next(s.s, s.e);
    return i;
}

static const char *utf8_offset(lu_Slice s, lua_Integer off, lua_Integer idx) {
    const char *p = s.s + off - 1;
    if (idx >= 0) {
        while (p < s.e && idx > 0) p = utf8_next(p, s.e), --idx;
        return idx == 0 ? p : NULL;
    } else {
        while (s.s < p && idx < 0) p = utf8_prev(s.s, p), ++idx;
        return idx == 0 ? p : NULL;
    }
}

static const char *utf8_relat(lu_Slice s, int idx) {
    return idx >= 0 ? utf8_offset(s, 1, idx - 1)
                    : utf8_offset(s, s.e - s.s + 1, idx);
}

static int utf8_range(lu_Slice s, lua_Integer *i, lua_Integer *j) {
    const char *ps = utf8_relat(s, CAST(int, *i));
    const char *pe = utf8_relat(s, CAST(int, *j));
    *i = (ps ? ps : (*i > 0 ? s.e : s.s)) - s.s;
    *j = (pe ? utf8_next(pe, s.e) : (*j > 0 ? s.e : s.s)) - s.s;
    return *i < *j;
}

/* Indexed by top nibble of first byte in code unit */
static uint8_t utf8_code_unit_len[] = {1,  1,  1,  1,  1, 1, 1, 1,
                                       -1, -1, -1, -1, 2, 2, 3, 4};

/* Check a multi-byte sequence starting at 's'; return s if invalid, else NULL
 */
static const char *utf8_invalid_sequence(lu_Slice sl, uint8_t c) {
    const char *s = sl.s, *e = sl.e;
    uint8_t     needed_bytes = utf8_code_unit_len[c >> 4];
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
static const char *utf8_invalid_offset(lu_Slice sl) {
    const char *s = sl.s, *e = sl.e;
    while (s < e) {
        uint8_t c = *s;
        if (c >= 0x80) {
            /* At the start of a sequence:
             * - c < 0xC0: continuation byte, invalid here.
             * - c < 0xC2: overlong 2-byte lead.
             * - c >= 0xF5: invalid codepoint > U+10FFFF or 0xFE/0xFF. */
            if (c < 0xC2 || c >= 0xF5) return s;
            if (utf8_invalid_sequence(lu_newslice(s, e - s), c)) return s;
            s += utf8_code_unit_len[c >> 4];
        } else {
            s++;
        }
    }
    return NULL;
}

/* Unicode character categories */

#define table_size(t) (sizeof(t) / sizeof((t)[0]))

#define utf8_categories(X) \
    X('a', alpha)          \
    X('c', cntrl)          \
    X('d', digit)          \
    X('l', lower)          \
    X('p', punct)          \
    X('s', space)          \
    X('t', compose)        \
    X('u', upper)          \
    X('x', xdigit)

#define utf8_converters(X) \
    X(lower)               \
    X(upper)               \
    X(title)               \
    X(fold)

static int find_in_range(range_table *t, size_t size, utfint ch) {
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

static int convert_char(conv_table *t, size_t size, utfint ch) {
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

static int lookup_canon_cls(utfint ch) {
    /* The first codepoint with canonicalization class != 0 is U+0300 COMBINING
     * GRAVE ACCENT */
    if (ch < 0x300) {
        return 0;
    }
    size_t begin = 0, end = table_size(nfc_combining_table);

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

static nfc_table *nfc_quickcheck(utfint ch) {
    /* The first character which needs to be checked for possible NFC violations
     * is U+0300 COMBINING GRAVE ACCENT */
    size_t begin = 0, end;
    if (ch < 0x300) return NULL;
    end = table_size(nfc_quickcheck_table);

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

static int nfc_combine(utfint cp1, utfint cp2, utfint *dest) {
    size_t       begin = 0, end = table_size(nfc_composite_table);
    unsigned int hash = (cp1 * 213) + cp2;

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

static decompose_table *nfc_decompose(utfint ch) {
    size_t begin = 0, end = table_size(nfc_decompose_table);

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

static int nfc_check_starter_can_combine(
        utfint ch, utfint starter, unsigned int prev_canon_cls) {
    if (!prev_canon_cls && nfc_combine(starter, ch, NULL)) return 0;
    return 1;
}

static int nfc_check_combining_mark(
        utfint ch, utfint starter, unsigned int canon_cls,
        unsigned int prev_canon_cls) {
    decompose_table *decomp, *decomp2;
    if (canon_cls <= prev_canon_cls) return 1;
    if (nfc_combine(starter, ch, NULL)) return 0;
    decomp = nfc_decompose(starter);
    if (decomp) {
        if (decomp->canon_cls2 > canon_cls
            && nfc_combine(decomp->to1, ch, NULL))
            return 0;
        decomp2 = nfc_decompose(decomp->to1);
        if (decomp2 && decomp2->canon_cls2 > canon_cls
            && nfc_combine(decomp2->to1, ch, NULL))
            return 0;
    }
    return 1;
}

static int nfc_check_jamo_vowel(utfint starter, unsigned int prev_canon_cls) {
    if (!prev_canon_cls && starter >= 0x1100 && starter <= 0x1112) return 0;
    return 1;
}

static int nfc_check_jamo_trailing(
        utfint starter, unsigned int prev_canon_cls) {
    if (!prev_canon_cls && starter >= 0xAC00 && starter <= 0xD7A3
        && (starter - 0xAC00) % 28 == 0)
        return 0;
    return 1;
}

static int nfc_check(
        utfint ch, nfc_table *entry, utfint starter, unsigned int canon_cls,
        unsigned int prev_canon_cls) {
    switch (entry->reason) {
    case REASON_MUST_CONVERT_1:
    case REASON_MUST_CONVERT_2: return 0;
    case REASON_STARTER_CAN_COMBINE:
        return nfc_check_starter_can_combine(ch, starter, prev_canon_cls);
    case REASON_COMBINING_MARK:
        return nfc_check_combining_mark(ch, starter, canon_cls, prev_canon_cls);
    case REASON_JAMO_VOWEL:
        return nfc_check_jamo_vowel(starter, prev_canon_cls);
    case REASON_JAMO_TRAILING:
        return nfc_check_jamo_trailing(starter, prev_canon_cls);
    default: return 1;
    }
}

static void merge_combining_marks(
        uint32_t *src1, uint32_t *src2, uint32_t *dest, size_t size1,
        size_t size2) {
    while (size1 && size2) {
        if ((*src1 & 0xFF) > (*src2 & 0xFF)) {
            *dest++ = *src2++;
            size2--;
        } else {
            *dest++ = *src1++;
            size1--;
        }
    }
    while (size1) {
        *dest++ = *src1++;
        size1--;
    }
    while (size2) {
        *dest++ = *src2++;
        size2--;
    }
}

/* Merge one bottom-up pass of runs of length 'runsize'; swaps src/dest */
static void merge_combining_marks_pass(
        uint32_t **psrc, uint32_t **pdest, size_t size, size_t runsize) {
    uint32_t *src = *psrc, *dest = *pdest, *temp;
    size_t    blocksize = runsize * 2;
    size_t    limit = size & ~(blocksize - 1);
    size_t    i;
    for (i = 0; i < limit; i += blocksize)
        merge_combining_marks(
                &src[i], &src[i + runsize], &dest[i], runsize, runsize);
    if (size - limit > runsize) {
        merge_combining_marks(
                &src[limit], &src[limit + runsize], &dest[limit], runsize,
                size - limit - runsize);
    } else {
        memcpy(&dest[limit], &src[limit], (size - limit) * sizeof(uint32_t));
    }
    temp = src;
    src = dest;
    dest = temp;
    *psrc = src;
    *pdest = dest;
}

static void stable_sort_combining_marks(
        uint32_t *vector, uint32_t *scratch, size_t size) {
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

    src = vector;
    dest = scratch;
    runsize = 2;
    while (runsize < size) {
        merge_combining_marks_pass(&src, &dest, size, runsize);
        runsize *= 2;
    }
    if (dest == vector) memcpy(vector, scratch, size * sizeof(uint32_t));
}

/* Shuffle item `i` up or down to get it into the right position */
static void stable_insert_combining_mark(
        uint32_t *vector, size_t vec_size, unsigned int i) {
    unsigned int item = vector[i];
    unsigned int canon_cls = item & 0xFF;
    if (i > 0) {
        if (canon_cls < (vector[i - 1] & 0xFF)) {
            do {
                vector[i] = vector[i - 1];
                i--;
            } while (i > 0 && canon_cls < (vector[i - 1] & 0xFF));
            vector[i] = item;
            return;
        }
    }
    if (i < vec_size - 1) {
        if (canon_cls > (vector[i + 1] & 0xFF)) {
            do {
                vector[i] = vector[i + 1];
                i++;
            } while (i < vec_size - 1 && canon_cls > (vector[i + 1] & 0xFF));
            vector[i] = item;
            return;
        }
    }
}

static void add_utf8char(luaL_Buffer *b, utfint ch);

static inline void grow_vector_if_needed(
        uint32_t **vector, uint32_t *onstack, size_t *size, size_t needed) {
    size_t current_size = *size;
    if (needed >= current_size) {
        /* `needed` is never bigger than `current_size * 2`. */
        size_t    new_size = current_size * 2;
        uint32_t *new_vector = malloc(new_size * sizeof(uint32_t));
        memcpy(new_vector, *vector, current_size * sizeof(uint32_t));
        *size = new_size;
        if (*vector != onstack) free(*vector);
        *vector = new_vector;
    }
}

/* NFC conversion state: process starter + combining-mark sequences, sorting
 * marks and combining them where possible. */
typedef struct NfcCtx {
    lua_State   *L;
    luaL_Buffer *buff;
    const char  *s, *e, *to_copy;
    utfint       starter, ch;
    unsigned int canon_cls, prev_canon_cls;
    int          fixedup;
    uint32_t     onstack[8];
    size_t       vec_size, vec_max;
    uint32_t    *vector;
    nfc_table   *entry;
} NfcCtx;

/* Sort accumulated combining marks if they are out of canonical order. */
static void nfc_sort_combining_marks(NfcCtx *ctx) {
    size_t i;
    for (i = 1; i < ctx->vec_size; i++) {
        if ((ctx->vector[i - 1] & 0xFF) > (ctx->vector[i] & 0xFF)) {
            uint32_t *scratch = malloc(ctx->vec_size * sizeof(uint32_t));
            stable_sort_combining_marks(ctx->vector, scratch, ctx->vec_size);
            free(scratch);
            ctx->fixedup = 1;
            break;
        }
    }
}

/* Handle a combining mark that must become one codepoint; returns continue. */
static int nfc_fix_must_convert_1(NfcCtx *ctx, size_t i) {
    nfc_table *mark_entry = nfc_quickcheck(ctx->vector[i] >> 8);
    ctx->vector[i] = (mark_entry->data1 << 8) | mark_entry->data2;
    ctx->fixedup = 1;
    return 1;
}

/* Handle a combining mark that must become two codepoints; returns continue. */
static int nfc_fix_must_convert_2(NfcCtx *ctx, size_t i) {
    nfc_table *mark_entry = nfc_quickcheck(ctx->vector[i] >> 8);
    grow_vector_if_needed(
            &ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 1);
    memmove(&ctx->vector[i + 2], &ctx->vector[i + 1],
            sizeof(uint32_t) * (ctx->vec_size - i - 1));
    ctx->vector[i] = (mark_entry->data1 << 8)
                   | lookup_canon_cls(mark_entry->data1);
    ctx->vector[i + 1] = (mark_entry->data2 << 8)
                       | lookup_canon_cls(mark_entry->data2);
    ctx->vec_size++;
    ctx->fixedup = 1;
    return 1;
}

static int nfc_fix_combining_mark_decomp2(
        NfcCtx *ctx, size_t i, unsigned int mark_canon_cls, utfint combine_mark,
        decompose_table *decomp) {
    decompose_table *decomp2 = nfc_decompose(decomp->to1);
    if (!decomp2 || decomp2->canon_cls2 <= mark_canon_cls
        || !nfc_combine(decomp2->to1, combine_mark, &ctx->starter))
        return 0;
    grow_vector_if_needed(
            &ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 1);
    memmove(&ctx->vector[i + 2], &ctx->vector[i + 1],
            sizeof(uint32_t) * (ctx->vec_size - i - 1));
    memmove(&ctx->vector[2], &ctx->vector[0], sizeof(uint32_t) * i);
    ctx->vector[0] = (decomp2->to2 << 8) | lookup_canon_cls(decomp2->to2);
    ctx->vector[1] = (decomp->to2 << 8) | lookup_canon_cls(decomp->to2);
    ctx->vec_size++;
    stable_insert_combining_mark(ctx->vector, ctx->vec_size, 1);
    stable_insert_combining_mark(ctx->vector, ctx->vec_size, 0);
    ctx->fixedup = 1;
    return 1;
}

static int nfc_fix_combining_mark_decomp(
        NfcCtx *ctx, size_t i, unsigned int mark_canon_cls,
        utfint combine_mark) {
    decompose_table *decomp;
    unsigned int     class2;
    decomp = nfc_decompose(ctx->starter);
    if (!decomp) return 0;
    if (decomp->canon_cls2 > mark_canon_cls
        && nfc_combine(decomp->to1, combine_mark, &ctx->starter)) {
        class2 = lookup_canon_cls(decomp->to2);
        memmove(&ctx->vector[1], &ctx->vector[0], sizeof(uint32_t) * i);
        ctx->vector[0] = (decomp->to2 << 8) | class2;
        stable_insert_combining_mark(ctx->vector, ctx->vec_size, 0);
        ctx->fixedup = 1;
        return 1;
    }
    return nfc_fix_combining_mark_decomp2(
            ctx, i, mark_canon_cls, combine_mark, decomp);
}

/* Try to combine/fix one combining mark; returns continue flag. */
static int nfc_fix_combining_mark(NfcCtx *ctx, size_t i) {
    unsigned int mark_canon_cls = ctx->vector[i] & 0xFF;
    utfint       combine_mark = ctx->vector[i] >> 8;
    if (i != 0 && mark_canon_cls <= (ctx->vector[i - 1] & 0xFF)) return 0;
    if (nfc_combine(ctx->starter, combine_mark, &ctx->starter)) {
        ctx->vec_size--;
        memmove(&ctx->vector[i], &ctx->vector[i + 1],
                sizeof(uint32_t) * (ctx->vec_size - i));
        ctx->fixedup = 1;
        return 1;
    }
    return nfc_fix_combining_mark_decomp(ctx, i, mark_canon_cls, combine_mark);
}

/* Fix one vector entry; returns 1 when the index must not advance. */
static int nfc_fix_one_combining_mark(NfcCtx *ctx, size_t i) {
    nfc_table *mark_entry = nfc_quickcheck(ctx->vector[i] >> 8);
    if (!mark_entry) return 0;
    switch (mark_entry->reason) {
    case REASON_MUST_CONVERT_1: return nfc_fix_must_convert_1(ctx, i);
    case REASON_MUST_CONVERT_2: return nfc_fix_must_convert_2(ctx, i);
    case REASON_COMBINING_MARK: return nfc_fix_combining_mark(ctx, i);
    default: return 0;
    }
}

static void nfc_emit_combining_marks(NfcCtx *ctx) {
    size_t i;
    if (ctx->fixedup) {
        if (ctx->starter != (utfint)-1) add_utf8char(ctx->buff, ctx->starter);
        for (i = 0; i < ctx->vec_size; i++)
            add_utf8char(ctx->buff, ctx->vector[i] >> 8);
    } else {
        luaL_addlstring(ctx->buff, ctx->to_copy, ctx->s - ctx->to_copy);
    }
}

/* Process accumulated combining marks and emit the preceding sequence. */
static int nfc_process_combining_marks(NfcCtx *ctx) {
    size_t i;
    nfc_sort_combining_marks(ctx);
    i = 0;
    while (i < ctx->vec_size) {
        if (nfc_fix_one_combining_mark(ctx, i)) continue;
        i++;
    }
    nfc_emit_combining_marks(ctx);
    if (ctx->s >= ctx->e) return 1;
    ctx->vec_size = 0;
    ctx->fixedup = 0;
    return 0;
}

static void nfc_accumulate_combining_mark(NfcCtx *ctx) {
    grow_vector_if_needed(
            &ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 1);
    ctx->vector[ctx->vec_size++] = (ctx->ch << 8) | (ctx->canon_cls & 0xFF);
}

/* Handle a deprecated starter that splits into two combining marks. */
static int nfc_handle_must_convert_2_starter(NfcCtx *ctx, const char *new_s) {
    utfint       conv1, conv2;
    unsigned int canon_cls1, canon_cls2;
    if (!ctx->entry || ctx->entry->reason != REASON_MUST_CONVERT_2) return 0;
    conv1 = ctx->entry->data1;
    canon_cls1 = lookup_canon_cls(conv1);
    if (!canon_cls1) return 0;
    conv2 = ctx->entry->data2;
    canon_cls2 = lookup_canon_cls(conv2);
    grow_vector_if_needed(
            &ctx->vector, ctx->onstack, &ctx->vec_max, ctx->vec_size + 2);
    ctx->vector[ctx->vec_size++] = (conv1 << 8) | (canon_cls1 & 0xFF);
    ctx->vector[ctx->vec_size++] = (conv2 << 8) | (canon_cls2 & 0xFF);
    ctx->s = new_s;
    ctx->prev_canon_cls = canon_cls2;
    ctx->fixedup = 1;
    return 1;
}

/* Handle a starter that directly follows another starter. */
static void nfc_handle_starter_starter(NfcCtx *ctx) {
    ctx->fixedup = 0;
    if (ctx->entry) {
        if (ctx->entry->reason == REASON_STARTER_CAN_COMBINE
            && nfc_combine(ctx->starter, ctx->ch, &ctx->ch)) {
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
    if (!ctx->fixedup) add_utf8char(ctx->buff, ctx->starter);
}

static void nfc_convert_starter_split(
        NfcCtx *ctx, utfint conv1, utfint conv2, unsigned int canon_cls2,
        unsigned int canon_cls3) {
    nfc_table *conv_entry = nfc_quickcheck(conv1);
    utfint     conv3;
    if (conv_entry && conv_entry->reason == REASON_MUST_CONVERT_2) {
        conv3 = conv2;
        conv1 = conv_entry->data1;
        conv2 = conv_entry->data2;
        canon_cls2 = lookup_canon_cls(conv2);
        if (canon_cls2) {
            ctx->starter = conv1;
            ctx->vector[0] = (conv2 << 8) | canon_cls2;
            ctx->vector[1] = (conv3 << 8) | canon_cls3;
            ctx->vec_size = 2;
        } else {
            add_utf8char(ctx->buff, conv1);
            ctx->starter = conv2;
            ctx->vector[0] = (conv3 << 8) | canon_cls3;
            ctx->vec_size = 1;
        }
        ctx->canon_cls = canon_cls3;
    } else {
        ctx->starter = conv1;
        ctx->vector[0] = (conv2 << 8) | canon_cls2;
        ctx->vec_size = 1;
        ctx->canon_cls = canon_cls2;
    }
    ctx->fixedup = 1;
}

/* Convert a starter to its canonical variant, if needed. */
static void nfc_convert_starter(NfcCtx *ctx) {
    utfint       conv1, conv2;
    unsigned int canon_cls2;
    if (!ctx->entry) return;
    if (ctx->entry->reason == REASON_MUST_CONVERT_1) {
        ctx->starter = ctx->entry->data1;
        ctx->fixedup = 1;
        return;
    }
    if (ctx->entry->reason != REASON_MUST_CONVERT_2) return;
    conv1 = ctx->entry->data1;
    conv2 = ctx->entry->data2;
    canon_cls2 = lookup_canon_cls(conv2);
    if (!canon_cls2) {
        add_utf8char(ctx->buff, conv1);
        ctx->starter = conv2;
        ctx->fixedup = 1;
        return;
    }
    nfc_convert_starter_split(ctx, conv1, conv2, canon_cls2, canon_cls2);
}

/* Handle a starter codepoint; returns 1 to continue, 2 when finished. */
static int nfc_handle_starter(NfcCtx *ctx, const char *new_s) {
    ctx->entry = nfc_quickcheck(ctx->ch);
    if (nfc_handle_must_convert_2_starter(ctx, new_s)) return 1;
    if (ctx->prev_canon_cls) {
        if (nfc_process_combining_marks(ctx)) return 2;
    } else if (ctx->starter != (utfint)-1) {
        nfc_handle_starter_starter(ctx);
    }
    ctx->starter = ctx->ch;
    ctx->to_copy = ctx->s;
    nfc_convert_starter(ctx);
    return 0;
}

static void nfc_ctx_init(NfcCtx *c, lua_State *L, luaL_Buffer *b, lu_Slice v) {
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

static void nfc_ctx_free(NfcCtx *ctx) {
    if (ctx->vector != ctx->onstack) free(ctx->vector);
}

static void nfc_run(NfcCtx *ctx) {
    int r;
    while (ctx->s < ctx->e) {
        const char *new_s = utf8_decode(ctx->s, &ctx->ch, 1);
        if (new_s == NULL) {
            nfc_ctx_free(ctx);
            luaL_error(ctx->L, "string is not valid UTF-8");
        }
        ctx->canon_cls = lookup_canon_cls(ctx->ch);
        if (!ctx->canon_cls) {
            r = nfc_handle_starter(ctx, new_s);
            if (r == 1) continue;
            if (r == 2) {
                nfc_ctx_free(ctx);
                return;
            }
        } else {
            nfc_accumulate_combining_mark(ctx);
        }
        ctx->s = new_s;
        ctx->prev_canon_cls = ctx->canon_cls;
    }
    if (ctx->vec_size && nfc_process_combining_marks(ctx)) {
        nfc_ctx_free(ctx);
        return;
    }
    if (ctx->starter != (utfint)-1) add_utf8char(ctx->buff, ctx->starter);
    nfc_ctx_free(ctx);
}

static void string_to_nfc(lua_State *L, luaL_Buffer *b, lu_Slice v) {
    NfcCtx ctx;
    nfc_ctx_init(&ctx, L, b, v);
    nfc_run(&ctx);
}

/* Grapheme cluster support */

static int hangul_type(utfint ch) {
    /* The first Hangul codepoint is U+1100 */
    if (ch < 0x1100) {
        return 0;
    }
    size_t begin = 0, end = table_size(hangul_table);

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

static int indic_conjunct_type(utfint ch) {
    /* The first Indic conjunct codepoint is U+0300 */
    if (ch < 0x300) {
        return 0;
    }
    size_t begin = 0, end = table_size(indic_table);

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

#define define_category(cls, name)                                        \
    static int utf8_is##name(utfint ch) {                                 \
        return find_in_range(name##_table, table_size(name##_table), ch); \
    }
#define define_converter(name)                                       \
    static utfint utf8_to##name(utfint ch) {                         \
        return convert_char(                                         \
                to##name##_table, table_size(to##name##_table), ch); \
    }
utf8_categories(define_category)
utf8_converters(define_converter)
#undef define_category
#undef define_converter

static int utf8_isgraph(utfint ch) {
    if (find_in_range(space_table, table_size(space_table), ch)) return 0;
    if (find_in_range(graph_table, table_size(graph_table), ch)) return 1;
    if (find_in_range(compose_table, table_size(compose_table), ch)) return 1;
    return 0;
}

static int utf8_isalnum(utfint ch) {
    if (find_in_range(alpha_table, table_size(alpha_table), ch)) return 1;
    if (find_in_range(alnum_extend_table, table_size(alnum_extend_table), ch))
        return 1;
    return 0;
}

static int utf8_width(utfint ch, int ambiwidth, int default_width) {
    if (find_in_range(unprintable_table, table_size(unprintable_table), ch))
        return default_width;
    if (find_in_range(compose_table, table_size(compose_table), ch))
        return default_width;
    if (find_in_range(doublewidth_table, table_size(doublewidth_table), ch))
        return 2;
    if (find_in_range(ambiwidth_table, table_size(ambiwidth_table), ch))
        return ambiwidth;
    return 1;
}

/* string module compatible interface */

static int typeerror(lua_State *L, int idx, const char *tname) {
    return luaL_error(L, "%s expected, got %s", tname, luaL_typename(L, idx));
}

static lu_Slice check_utf8(lua_State *L, int idx) {
    size_t      len;
    const char *s = luaL_checklstring(L, idx, &len);
    return lu_newslice(s, len);
}

static lu_Slice to_utf8(lua_State *L, int idx) {
    size_t      len;
    const char *s = lua_tolstring(L, idx, &len);
    return lu_newslice(s, len);
}

static const char *utf8_safe_decode(lua_State *L, const char *p, utfint *pval) {
    *pval = 0;
    p = utf8_decode(p, pval, 0);
    if (p == NULL) luaL_error(L, "invalid UTF-8 code");
    return p;
}

static void add_utf8char(luaL_Buffer *b, utfint ch) {
    char   buff[UTF8_BUFFSZ];
    size_t n = utf8_encode(buff, ch);
    luaL_addlstring(b, buff + UTF8_BUFFSZ - n, n);
}

static lua_Integer byte_relat(lua_Integer pos, size_t len) {
    if (pos >= 0)
        return pos;
    else if (0u - (size_t)pos > len)
        return 0;
    else
        return (lua_Integer)len + pos + 1;
}

static void check_byte_range(
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
    lua_Integer posi = byte_relat(luaL_optinteger(L, 2, 1), len);
    lua_Integer posj = byte_relat(luaL_optinteger(L, 3, len), len);
    int         lax = lua_toboolean(L, 4);
    check_byte_range(L, len, &posi, &posj);
    for (n = 0, p = s + posi, e = s + posj + 1; p < e; ++n) {
        if (lax)
            p = utf8_next(p, e);
        else {
            utfint      ch;
            const char *np = utf8_decode(p, &ch, !lax);
            if (np == NULL || utf8_invalid(ch)) {
                lua_pushnil(L);
                lua_pushinteger(L, p - s + 1);
                return 2;
            }
            p = np;
        }
    }
    lua_pushinteger(L, n);
    return 1;
}

static int Lutf8_sub(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer posi = luaL_checkinteger(L, 2);
    lua_Integer posj = luaL_optinteger(L, 3, -1);
    if (utf8_range(lu_newslice(s, e - s), &posi, &posj))
        lua_pushlstring(L, s + posi, posj - posi);
    else
        lua_pushliteral(L, "");
    return 1;
}

static int Lutf8_reverse(lua_State *L) {
    luaL_Buffer b;
    lu_Slice    sl = check_utf8(L, 1);
    const char *prev, *pprev, *ends, *e = sl.e, *s = sl.s;
    (void)ends;
    int lax = lua_toboolean(L, 2);
    luaL_buffinit(L, &b);
    if (lax) {
        for (prev = e; s < prev; e = prev) {
            prev = utf8_prev(s, prev);
            luaL_addlstring(&b, prev, e - prev);
        }
    } else {
        for (prev = e; s < prev; prev = pprev) {
            utfint code = 0;
            ends = utf8_safe_decode(L, pprev = utf8_prev(s, prev), &code);
            assert(ends == prev);
            if (utf8_invalid(code)) return luaL_error(L, "invalid UTF-8 code");
            if (!utf8_iscompose(code)) {
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
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer posi = luaL_optinteger(L, 2, 1);
    lua_Integer posj = luaL_optinteger(L, 3, posi);
    if (utf8_range(lu_newslice(s, e - s), &posi, &posj)) {
        for (e = s + posj, s = s + posi; s < e; ++n) {
            utfint ch = 0;
            s = utf8_safe_decode(L, s, &ch);
            lua_pushinteger(L, ch);
        }
    }
    return CAST(int, n);
}

static int Lutf8_codepoint(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    size_t      len = e - s;
    lua_Integer posi = byte_relat(luaL_optinteger(L, 2, 1), len);
    lua_Integer posj = byte_relat(luaL_optinteger(L, 3, posi), len);
    int         lax = lua_toboolean(L, 4);
    int         n;
    const char *se;
    luaL_argcheck(L, posi >= 1, 2, "out of bounds");
    luaL_argcheck(L, posj <= (lua_Integer)len, 3, "out of bounds");
    if (posi > posj) return 0;  /* empty interval; return no values */
    if (posj - posi >= INT_MAX) /* (lua_Integer -> int) overflow? */
        return luaL_error(L, "string slice too long");
    n = (int)(posj - posi + 1);
    luaL_checkstack(L, n, "string slice too long");
    n = 0;         /* count the number of returns */
    se = s + posj; /* string end */
    for (n = 0, s += posi - 1; s < se;) {
        utfint code = 0;
        s = utf8_safe_decode(L, s, &code);
        if (!lax && utf8_invalid(code))
            return luaL_error(L, "invalid UTF-8 code");
        lua_pushinteger(L, code);
        n++;
    }
    return n;
}

static int Lutf8_char(lua_State *L) {
    int         i, n = lua_gettop(L); /* number of arguments */
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    for (i = 1; i <= n; ++i) {
        utfint code = (utfint)luaL_checkinteger(L, i);
        luaL_argcheck(L, code <= UTF8_MAXCP, i, "value out of range");
        add_utf8char(&b, CAST(utfint, code));
    }
    luaL_pushresult(&b);
    return 1;
}

#define bind_converter(name)                                              \
    static int Lutf8_##name(lua_State *L) {                               \
        int t = lua_type(L, 1);                                           \
        if (t == LUA_TNUMBER)                                             \
            lua_pushinteger(                                              \
                    L, utf8_to##name(CAST(utfint, lua_tointeger(L, 1)))); \
        else if (t == LUA_TSTRING) {                                      \
            luaL_Buffer b;                                                \
            lu_Slice    sl = to_utf8(L, 1);                               \
            const char *s = sl.s, *e = sl.e;                              \
            luaL_buffinit(L, &b);                                         \
            while (s < e) {                                               \
                utfint ch = 0;                                            \
                s = utf8_safe_decode(L, s, &ch);                          \
                add_utf8char(&b, utf8_to##name(ch));                      \
            }                                                             \
            luaL_pushresult(&b);                                          \
        } else                                                            \
            return typeerror(L, 1, "number/string");                      \
        return 1;                                                         \
    }
utf8_converters(bind_converter)
#undef bind_converter

/* unicode extra interface */

static void parse_escape(lua_State *L, lu_Slice *sl, int hex, utfint *pch) {
    const char *s = sl->s, *e = sl->e;
    utfint      code = 0;
    int         in_bracket = 0;
    if (*s == '{') ++s, in_bracket = 1;
    for (; s < e; ++s) {
        utfint ch = (unsigned char)*s;
        if (ch >= '0' && ch <= '9')
            ch = ch - '0';
        else if (hex && ch >= 'A' && ch <= 'F')
            ch = 10 + (ch - 'A');
        else if (hex && ch >= 'a' && ch <= 'f')
            ch = 10 + (ch - 'a');
        else if (!in_bracket)
            break;
        else if (ch == '}') {
            ++s;
            break;
        } else
            luaL_error(L, "invalid escape '%c'", ch);
        code *= hex ? 16 : 10;
        code += ch;
    }
    *pch = code;
    sl->s = s;
}

static int parse_escape_prefix(lua_State *L, lu_Slice *sl, utfint *ch) {
    const char *s = sl->s, *e = sl->e;
    int         hex = 0;
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
        s = utf8_safe_decode(L, s, ch);
        sl->s = s;
        return 0;
    }
    sl->s = s;
    parse_escape(L, sl, hex, ch);
    return 1;
}

static int Lutf8_escape(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    while (sl.s < sl.e) {
        utfint ch = 0;
        sl.s = utf8_safe_decode(L, sl.s, &ch);
        if (ch == '%') parse_escape_prefix(L, &sl, &ch);
        add_utf8char(&b, ch);
    }
    luaL_pushresult(&b);
    return 1;
}

static int Lutf8_insert(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    size_t      sublen;
    const char *subs;
    luaL_Buffer b;
    int         nargs = 2;
    const char *first = e;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        int idx = (int)lua_tointeger(L, 2);
        if (idx != 0) first = utf8_relat(lu_newslice(s, e - s), idx);
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
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer posi = luaL_optinteger(L, 2, -1);
    lua_Integer posj = luaL_optinteger(L, 3, -1);
    if (!utf8_range(lu_newslice(s, e - s), &posi, &posj))
        lua_settop(L, 1);
    else {
        luaL_Buffer b;
        luaL_buffinit(L, &b);
        luaL_addlstring(&b, s, posi);
        luaL_addlstring(&b, s + posj, e - s - posj);
        luaL_pushresult(&b);
    }
    return 1;
}

static int push_offset(lua_State *L, lu_Slice v, lua_Integer o, lua_Integer i) {
    utfint      ch = 0;
    const char *p;
    if (i != 0)
        p = utf8_offset(v, o, i);
    else if (p = v.s + o - 1, iscontp(p))
        p = utf8_prev(v.s, p);
    if (p == NULL || p == v.e) return 0;
    utf8_decode(p, &ch, 0);
    lua_pushinteger(L, p - v.s + 1);
    lua_pushinteger(L, ch);
    return 2;
}

static int Lutf8_charpos(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer offset = 1;
    if (lua_isnoneornil(L, 3)) {
        lua_Integer idx = luaL_optinteger(L, 2, 0);
        if (idx > 0)
            --idx;
        else if (idx < 0)
            offset = e - s + 1;
        return push_offset(L, sl, offset, idx);
    }
    offset = byte_relat(luaL_optinteger(L, 2, 1), e - s);
    if (offset < 1) offset = 1;
    return push_offset(L, sl, offset, luaL_checkinteger(L, 3));
}

static void utf8_move_back(const char *s, lua_Integer *pposi, lua_Integer *pn) {
    lua_Integer posi = *pposi, n = *pn;
    while (n < 0 && posi > 0) { /* move back */
        do {                    /* find beginning of previous character */
            posi--;
        } while (posi > 0 && iscontp(s + posi));
        n++;
    }
    *pposi = posi;
    *pn = n;
}

static void utf8_move_forward(
        const char *s, lua_Integer len, lua_Integer *pposi, lua_Integer *pn) {
    lua_Integer posi = *pposi, n = *pn;
    n--; /* do not move for 1st character */
    while (n > 0 && posi < len) {
        do { /* find beginning of next character */
            posi++;
        } while (iscontp(s + posi)); /* (cannot pass final '\0') */
        n--;
    }
    *pposi = posi;
    *pn = n;
}

static lua_Integer utf8_end_offset(const char *s, lua_Integer posi) {
    if ((s[posi] & 0x80) != 0) {
        do {
            posi++;
        } while (iscontp(s + posi + 1));
    }
    /* else one-byte character: final position is the initial one */
    return posi + 1;
}

static int Lutf8_offset(lua_State *L) {
    size_t      len;
    const char *s = luaL_checklstring(L, 1, &len);
    lua_Integer n = luaL_checkinteger(L, 2);
    lua_Integer posi = (n >= 0) ? 1 : len + 1;
    posi = byte_relat(luaL_optinteger(L, 3, posi), len);
    luaL_argcheck(
            L, 1 <= posi && --posi <= (lua_Integer)len, 3,
            "position out of range");
    if (n == 0) {
        /* find beginning of current byte sequence */
        while (posi > 0 && iscontp(s + posi)) posi--;
    } else {
        if (iscontp(s + posi))
            return luaL_error(L, "initial position is a continuation byte");
        if (n < 0)
            utf8_move_back(s, &posi, &n);
        else
            utf8_move_forward(s, (lua_Integer)len, &posi, &n);
    }
    if (n != 0) return lua_pushnil(L), 1;
    lua_pushinteger(L, posi + 1);
    lua_pushinteger(L, utf8_end_offset(s, posi));
    return 2;
}

static int Lutf8_next(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    lua_Integer offset = byte_relat(luaL_optinteger(L, 2, 1), e - s);
    lua_Integer idx = luaL_optinteger(L, 3, !lua_isnoneornil(L, 2));
    return push_offset(L, sl, offset, idx);
}

static int iter_aux(lua_State *L, int strict) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    int         n = CAST(int, lua_tointeger(L, 2));
    const char *p = n <= 0 ? s : utf8_next(s + n - 1, e);
    if (p < e) {
        utfint code = 0;
        utf8_safe_decode(L, p, &code);
        if (strict && utf8_invalid(code))
            return luaL_error(L, "invalid UTF-8 code");
        lua_pushinteger(L, p - s + 1);
        lua_pushinteger(L, code);
        return 2;
    }
    return 0; /* no more codepoints */
}

static int iter_auxstrict(lua_State *L) { return iter_aux(L, 1); }
static int iter_auxlax(lua_State *L) { return iter_aux(L, 0); }

static int Lutf8_codes(lua_State *L) {
    int lax = lua_toboolean(L, 2);
    luaL_checkstring(L, 1);
    lua_pushcfunction(L, lax ? iter_auxlax : iter_auxstrict);
    lua_pushvalue(L, 1);
    lua_pushinteger(L, 0);
    return 3;
}

static int width_opt(lua_State *L, int idx, int *pdefault) {
    int ambiwidth = CAST(int, luaL_optinteger(L, idx, 1));
    if (pdefault != NULL) *pdefault = CAST(int, luaL_optinteger(L, idx + 1, 0));
    return ambiwidth;
}

static int lutf8_width_string(lua_State *L) {
    size_t      len;
    const char *e, *s = luaL_checklstring(L, 1, &len);
    lua_Integer posi = byte_relat(luaL_optinteger(L, 2, 1), len);
    lua_Integer posj = byte_relat(luaL_optinteger(L, 3, len), len);
    int         width = 0, ambiwidth, default_width;
    ambiwidth = width_opt(L, 4, &default_width);
    luaL_argcheck(
            L, 1 <= posi && --posi <= (lua_Integer)len, 2,
            "initial position out of bounds");
    luaL_argcheck(
            L, --posj < (lua_Integer)len, 3, "final position out of bounds");
    e = s + posj + 1, s += posi;
    while (s < e) {
        utfint ch = 0;
        s = utf8_safe_decode(L, s, &ch);
        width += utf8_width(ch, ambiwidth, default_width);
    }
    return lua_pushinteger(L, (lua_Integer)width), 1;
}

static int Lutf8_width(lua_State *L) {
    int t = lua_type(L, 1);
    int ambiwidth, default_width, w;
    if (t != LUA_TNUMBER && t != LUA_TSTRING)
        return typeerror(L, 1, "number/string");
    if (t == LUA_TSTRING) return lutf8_width_string(L);
    ambiwidth = width_opt(L, 2, &default_width);
    w = utf8_width(CAST(utfint, lua_tointeger(L, 1)), ambiwidth, default_width);
    return lua_pushinteger(L, w), 1;
}

static int Lutf8_widthindex(lua_State *L) {
    size_t      len;
    const char *e, *s = luaL_checklstring(L, 1, &len);
    int         chwidth, width = CAST(int, luaL_checkinteger(L, 2));
    lua_Integer posi = byte_relat(luaL_optinteger(L, 3, 1), len);
    lua_Integer posj = byte_relat(luaL_optinteger(L, 4, len), len), idx;
    int         default_width, ambiwidth = width_opt(L, 5, &default_width);
    check_byte_range(L, len, &posi, &posj);
    for (idx = 0, e = s + posj + 1, s += posi; s < e; ++idx, width -= chwidth) {
        utfint ch = 0;
        s = utf8_safe_decode(L, s, &ch);
        chwidth = utf8_width(ch, ambiwidth, default_width);
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
    lua_Integer posi = byte_relat(luaL_optinteger(L, 3, 1), len);
    lua_Integer posj = byte_relat(luaL_optinteger(L, 4, len), len);
    int    chwidth, default_width, ambiwidth = width_opt(L, 5, &default_width);
    utfint ch;
    check_byte_range(L, len, &posi, &posj);
    s = h + posi, e = h + posj + 1;
    if (width >= 0) {
        for (; s < e && width != 0; s = n, width -= chwidth) {
            n = utf8_safe_decode(L, s, &ch);
            chwidth = utf8_width(ch, ambiwidth, default_width);
            if (width < chwidth) break;
        }
        lua_pushinteger(L, s - h);
    } else {
        for (; s < e && width != 0; e = n, width += chwidth) {
            utf8_safe_decode(L, n = utf8_prev(s, e), &ch);
            chwidth = utf8_width(ch, ambiwidth, default_width);
            if (-width < chwidth) break;
        }
        lua_pushinteger(L, e - h + 1);
    }
    lua_pushinteger(L, width);
    return 2;
}

static int Lutf8_ncasecmp(lua_State *L) {
    lu_Slice    sl1 = check_utf8(L, 1);
    const char *s1 = sl1.s, *e1 = sl1.e;
    lu_Slice    sl2 = check_utf8(L, 2);
    const char *s2 = sl2.s, *e2 = sl2.e;
    while (s1 < e1 || s2 < e2) {
        utfint ch1 = 0, ch2 = 0;
        if (s1 == e1)
            ch2 = 1;
        else if (s2 == e2)
            ch1 = 1;
        else {
            s1 = utf8_safe_decode(L, s1, &ch1);
            s2 = utf8_safe_decode(L, s2, &ch2);
            ch1 = utf8_tofold(ch1);
            ch2 = utf8_tofold(ch2);
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

#ifndef LUA_MAXCAPTURES
# define LUA_MAXCAPTURES 32
#endif /* LUA_MAXCAPTURES */

#define CAP_UNFINISHED (-1)
#define CAP_POSITION   (-2)

typedef struct MatchState {
    int matchdepth; /* control for recursive depth (to avoid C stack overflow)
                     */
    const char  *src_init; /* init of source string */
    const char  *src_end;  /* end ('\0') of source string */
    const char  *p;        /* current pattern start */
    const char  *p_end;    /* end ('\0') of pattern */
    int          tr;       /* replacement type for gsub */
    lua_Integer *pn;       /* substitution counter for gsub */
    lua_State   *L;
    int          level; /* total number of captures (finished or unfinished) */
    struct {
        const char *init;
        ptrdiff_t   len;
    } capture[LUA_MAXCAPTURES];
} MatchState;

/* recursive function */
static const char *match(MatchState *ms, const char *s, const char *p);

/* maximum recursion depth for 'match' */
#if !defined(MAXCCALLS)
#define MAXCCALLS 200
#endif

#define L_ESC    '%'
#define SPECIALS "^$*+?.([%-"

static int check_capture(MatchState *ms, int l) {
    l -= '1';
    if (l < 0 || l >= ms->level || ms->capture[l].len == CAP_UNFINISHED)
        return luaL_error(ms->L, "invalid capture index %%%d", l + 1);
    return l;
}

static int capture_to_close(MatchState *ms) {
    int level = ms->level;
    while (--level >= 0)
        if (ms->capture[level].len == CAP_UNFINISHED) return level;
    return luaL_error(ms->L, "invalid pattern capture");
}

static const char *classend(MatchState *ms, const char *p) {
    utfint ch = 0;
    p = utf8_safe_decode(ms->L, p, &ch);
    switch (ch) {
    case L_ESC:
        if (p == ms->p_end)
            luaL_error(ms->L, "malformed pattern (ends with " LUA_QL("%%") ")");
        return utf8_next(p, ms->p_end);
    case '[':
        if (*p == '^') p++;
        do { /* look for a `]' */
            if (p == ms->p_end)
                luaL_error(
                        ms->L, "malformed pattern (missing " LUA_QL("]") ")");
            if (*(p++) == L_ESC && p < ms->p_end)
                p++; /* skip escapes (e.g. `%]') */
        } while (*p != ']');
        return p + 1;
    default: return p;
    }
}

static int match_class(utfint c, utfint cl) {
    int res;
    switch (utf8_tolower(cl)) {
#define X(cls, name) \
    case cls: res = utf8_is##name(c); break;
        utf8_categories(X)
#undef X
    case 'g': res = utf8_isgraph(c); break;
    case 'w': res = utf8_isalnum(c); break;
    case 'z': res = (c == 0); break; /* deprecated option */
    default: return (cl == c);
    }
    return (utf8_islower(cl) ? res : !res);
}

static int matchbracketclass(
        MatchState *ms, utfint c, const char *p, const char *ec) {
    int sig = 1;
    assert(*p == '[');
    if (*++p == '^') {
        sig = 0;
        p++; /* skip the `^' */
    }
    while (p < ec) {
        utfint ch = 0;
        p = utf8_safe_decode(ms->L, p, &ch);
        if (ch == L_ESC) {
            p = utf8_safe_decode(ms->L, p, &ch);
            if (match_class(c, ch)) return sig;
        } else {
            utfint      next = 0;
            const char *np = utf8_safe_decode(ms->L, p, &next);
            if (next == '-' && np < ec) {
                p = utf8_safe_decode(ms->L, np, &next);
                if (ch <= c && c <= next) return sig;
            } else if (ch == c)
                return sig;
        }
    }
    return !sig;
}

static int singlematch(
        MatchState *ms, const char *s, const char *p, const char *ep) {
    if (s >= ms->src_end)
        return 0;
    else {
        utfint ch = 0, pch = 0;
        utf8_safe_decode(ms->L, s, &ch);
        p = utf8_safe_decode(ms->L, p, &pch);
        switch (pch) {
        case '.': return 1; /* matches any char */
        case L_ESC:
            utf8_safe_decode(ms->L, p, &pch);
            return match_class(ch, pch);
        case '[': return matchbracketclass(ms, ch, p - 1, ep - 1);
        default: return pch == ch;
        }
    }
}

static const char *matchbalance(MatchState *ms, const char *s, const char **p) {
    utfint ch = 0, begin = 0, end = 0;
    *p = utf8_safe_decode(ms->L, *p, &begin);
    if (*p >= ms->p_end)
        luaL_error(
                ms->L,
                "malformed pattern "
                "(missing arguments to " LUA_QL("%%b") ")");
    *p = utf8_safe_decode(ms->L, *p, &end);
    s = utf8_safe_decode(ms->L, s, &ch);
    if (ch != begin)
        return NULL;
    else {
        int cont = 1;
        while (s < ms->src_end) {
            s = utf8_safe_decode(ms->L, s, &ch);
            if (ch == end) {
                if (--cont == 0) return s;
            } else if (ch == begin)
                cont++;
        }
    }
    return NULL; /* string ends out of balance */
}

static const char *max_expand(
        MatchState *ms, const char *s, const char *p, const char *ep) {
    const char *m = s; /* matched end of single match p */
    while (singlematch(ms, m, p, ep)) m = utf8_next(m, ms->src_end);
    /* keeps trying to match with the maximum repetitions */
    while (s <= m) {
        const char *res = match(ms, m, ep + 1);
        if (res) return res;
        /* else didn't match; reduce 1 repetition to try again */
        if (s == m) break;
        m = utf8_prev(s, m);
    }
    return NULL;
}

static const char *min_expand(
        MatchState *ms, const char *s, const char *p, const char *ep) {
    for (;;) {
        const char *res = match(ms, s, ep + 1);
        if (res != NULL)
            return res;
        else if (singlematch(ms, s, p, ep))
            s = utf8_next(s, ms->src_end); /* try with one more repetition */
        else
            return NULL;
    }
}

static const char *start_capture(
        MatchState *ms, const char *s, const char *p, int what) {
    const char *res;
    int         level = ms->level;
    if (level >= LUA_MAXCAPTURES) luaL_error(ms->L, "too many captures");
    ms->capture[level].init = s;
    ms->capture[level].len = what;
    ms->level = level + 1;
    if ((res = match(ms, s, p)) == NULL) /* match failed? */
        ms->level--;                     /* undo capture */
    return res;
}

static const char *end_capture(MatchState *ms, const char *s, const char *p) {
    int         l = capture_to_close(ms);
    const char *res;
    ms->capture[l].len = s - ms->capture[l].init; /* close capture */
    if ((res = match(ms, s, p)) == NULL)          /* match failed? */
        ms->capture[l].len = CAP_UNFINISHED;      /* undo capture */
    return res;
}

static const char *match_capture(MatchState *ms, const char *s, int l) {
    size_t len;
    l = check_capture(ms, l);
    len = ms->capture[l].len;
    if ((size_t)(ms->src_end - s) >= len
        && memcmp(ms->capture[l].init, s, len) == 0)
        return s + len;
    else
        return NULL;
}

#define M_OK   0
#define M_FAIL 1
#define M_INIT 2
#define M_DFLT 3

/* Handle plain pattern elements; returns a MatchResult. */
static int match_basic(
        MatchState *ms, const char *s, const char *p, utfint ch,
        const char **ps) {
    switch (ch) {
    case '(':
        if (*(p + 1) == ')') /* position capture? */
            *ps = start_capture(ms, s, p + 2, CAP_POSITION);
        else
            *ps = start_capture(ms, s, p + 1, CAP_UNFINISHED);
        return M_OK;
    case ')': *ps = end_capture(ms, s, p + 1); return M_OK;
    case '$':
        if ((p + 1) != ms->p_end) return M_DFLT;
        *ps = (s == ms->src_end) ? s : NULL;
        return M_OK;
    }
    return M_FAIL;
}

static int match_escaped_balance(
        MatchState *ms, const char *s, const char *p, const char **ps,
        const char **pp) {
    s = matchbalance(ms, s, &p);
    if (s != NULL) {
        *ps = s;
        *pp = p;
        return M_INIT;
    }
    *ps = NULL;
    return M_FAIL;
}

static int match_escaped_frontier(
        MatchState *ms, const char *s, const char *p, const char **ps,
        const char **pp) {
    const char *ep;
    utfint      previous = 0, current = 0;
    if (*p != '[') luaL_error(ms->L, "missing '[' after '%%f' in pattern");
    ep = classend(ms, p);
    if (s != ms->src_init)
        utf8_decode(utf8_prev(ms->src_init, s), &previous, 0);
    if (s != ms->src_end) utf8_decode(s, &current, 0);
    if (!matchbracketclass(ms, previous, p, ep - 1)
        && matchbracketclass(ms, current, p, ep - 1)) {
        *ps = s;
        *pp = ep;
        return M_INIT;
    }
    *ps = NULL;
    return M_FAIL;
}

static int match_escaped_digit(
        MatchState *ms, const char *s, const char *p, utfint ch,
        const char **ps, const char **pp) {
    const char *res = match_capture(ms, s, ch);
    if (res != NULL) {
        *ps = res;
        *pp = p;
        return M_INIT;
    }
    *ps = NULL;
    return M_FAIL;
}

/* Handle an escaped pattern element after '%'; returns a MatchResult. */
static int match_escaped(
        MatchState *ms, const char *s, const char *p, const char *prev_p,
        utfint ch, const char **ps, const char **pp) {
    if (ch == 'b') return match_escaped_balance(ms, s, p, ps, pp);
    if (ch == 'f') return match_escaped_frontier(ms, s, p, ps, pp);
    if (ch >= '0' && ch <= '9')
        return match_escaped_digit(ms, s, p, ch, ps, pp);
    *pp = prev_p;
    return M_DFLT;
}

static int match_suffix(
        MatchState *ms, const char *s, const char *p, const char *ep,
        const char *next_s, const char **ps, const char **pp) {
    const char *res, *next_ep;
    switch (*ep) {
    case '?':
        next_ep = utf8_next(ep, ms->p_end);
        if ((res = match(ms, next_s, next_ep)) != NULL) {
            *ps = res;
            *pp = p;
            return M_OK;
        }
        *pp = next_ep;
        return M_INIT;
    case '+':
    case '*':
        *ps = max_expand(ms, (*ep == '+') ? next_s : s, p, ep);
        *pp = p;
        return M_OK;
    case '-':
        *ps = min_expand(ms, s, p, ep);
        *pp = p;
        return M_OK;
    default:
        *ps = next_s;
        *pp = ep;
        return M_INIT;
    }
}

/* Handle the default pattern-class suffix; returns a MatchResult. */
static int match_default(
        MatchState *ms, const char *s, const char *p, const char **ps,
        const char **pp) {
    const char *ep = classend(ms, p);
    const char *next_s;
    if (!singlematch(ms, s, p, ep)) {
        if (*ep == '*' || *ep == '?' || *ep == '-') {
            *pp = ep + 1;
            return M_INIT;
        }
        *ps = NULL;
        return M_FAIL;
    }
    next_s = utf8_next(s, ms->src_end);
    return match_suffix(ms, s, p, ep, next_s, ps, pp);
}

/* Execute one matching step; never returns M_DFLT to the caller. */
static int match_step(
        MatchState *ms, const char *s, const char *p, utfint ch,
        const char **ps, const char **pp) {
    const char *prev_p;
    utfint      esc_ch;
    int         r;
    switch (ch) {
    case '(':
    case ')':
    case '$':
        r = match_basic(ms, s, p, ch, ps);
        if (r == M_DFLT) return match_default(ms, s, p, ps, pp);
        return r;
    case L_ESC:
        prev_p = p;
        p = utf8_safe_decode(ms->L, p + 1, &esc_ch);
        r = match_escaped(ms, s, p, prev_p, esc_ch, ps, pp);
        if (r == M_DFLT) return match_default(ms, s, prev_p, ps, pp);
        return r;
    default: return match_default(ms, s, p, ps, pp);
    }
}

static const char *match(MatchState *ms, const char *s, const char *p) {
    if (ms->matchdepth-- == 0) luaL_error(ms->L, "pattern too complex");
init:                     /* using goto's to optimize tail recursion */
    if (p != ms->p_end) { /* end of pattern? */
        utfint ch = 0;
        int    r;
        utf8_safe_decode(ms->L, p, &ch);
        r = match_step(ms, s, p, ch, &s, &p);
        if (r == M_INIT) goto init;
        if (r == M_FAIL) s = NULL;
    }
    ms->matchdepth++;
    return s;
}

static const char *lmemfind(
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

static int get_index(const char *p, lu_Slice s) {
    int idx;
    for (idx = 0; s.s < s.e && s.s < p; ++idx) s.s = utf8_next(s.s, s.e);
    return s.s == p ? idx : idx - 1;
}

static void push_onecapture(MatchState *ms, int i, lu_Slice s) {
    if (i >= ms->level) {
        if (i == 0)                                 /* ms->level == 0, too */
            lua_pushlstring(ms->L, s.s, s.e - s.s); /* add whole match */
        else
            luaL_error(ms->L, "invalid capture index");
    } else {
        ptrdiff_t l = ms->capture[i].len;
        if (l == CAP_UNFINISHED) luaL_error(ms->L, "unfinished capture");
        if (l == CAP_POSITION) {
            int idx = get_index(
                    ms->capture[i].init,
                    lu_newslice(ms->src_init, ms->src_end - ms->src_init));
            lua_pushinteger(ms->L, idx + 1);
        } else
            lua_pushlstring(ms->L, ms->capture[i].init, l);
    }
}

static int push_captures(MatchState *ms, lu_Slice s) {
    int i;
    int nlevels = (ms->level == 0 && s.s) ? 1 : ms->level;
    luaL_checkstack(ms->L, nlevels, "too many captures");
    for (i = 0; i < nlevels; i++) push_onecapture(ms, i, s);
    return nlevels; /* number of strings pushed */
}

/* check whether pattern has no special characters */
static int nospecials(const char *p, const char *ep) {
    while (p < ep) {
        if (strpbrk(p, SPECIALS))
            return 0;       /* pattern has a special character */
        p += strlen(p) + 1; /* may have more after \0 */
    }
    return 1; /* no special chars found */
}

/* utf8 pattern matching interface */

static int find_plain(MatchState *ms, lu_Slice cur, lua_Integer idx) {
    const char *s = ms->src_init, *es = ms->src_end;
    const char *p = ms->p, *ep = ms->p_end;
    const char *s2, *e2;
    s2 = lmemfind(cur.s, cur.e - cur.s, p, ep - p);
    if (s2) {
        e2 = s2 + (ep - p);
        if (iscontp(e2)) e2 = utf8_next(e2, es);
        lua_pushinteger(ms->L, idx = get_index(s2, lu_newslice(s, es - s)) + 1);
        lua_pushinteger(
                ms->L, idx + get_index(e2, lu_newslice(s2, es - s2)) - 1);
        return 2;
    }
    return 0;
}

static int find_pattern_at(
        lua_State *L, MatchState *ms, const char *p, const char *init,
        lua_Integer idx, int find) {
    const char *res;
    ms->level = 0;
    assert(ms->matchdepth == MAXCCALLS);
    if ((res = match(ms, init, p)) != NULL) {
        if (find) {
            lua_pushinteger(L, idx); /* start */
            lua_pushinteger(
                    L, idx + utf8_length(lu_newslice(init, res - init))
                               - 1); /* end */
            return push_captures(ms, (lu_Slice){NULL, NULL}) + 2;
        } else
            return push_captures(ms, lu_newslice(init, res - init));
    }
    return 0;
}

static int find_pattern(MatchState *ms, lu_Slice cur, lua_Integer idx, int f) {
    const char *s = ms->src_init, *es = ms->src_end, *p = ms->p;
    const char *init = cur.s;
    int         anchor = (*p == '^');
    int         n;
    if (anchor) p++; /* skip anchor character */
    if (idx < 0)
        idx += utf8_length(lu_newslice(s, es - s)) + 1; /* TODO not very good */
    ms->matchdepth = MAXCCALLS;
    do {
        n = find_pattern_at(ms->L, ms, p, init, idx, f);
        if (n) return n;
        if (init == es) break;
        idx += 1;
        init = utf8_next(init, es);
    } while (init <= es && !anchor);
    return 0;
}

static int find_aux(lua_State *L, int find) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *es = sl.e;
    lu_Slice    pl = check_utf8(L, 2);
    const char *p = pl.s, *ep = pl.e;
    lua_Integer idx = luaL_optinteger(L, 3, 1);
    MatchState  ms;
    const char *init;
    int         n;
    if (!idx) idx = 1;
    init = utf8_relat(lu_newslice(s, es - s), CAST(int, idx));
    if (init == NULL) {
        if (idx > 0) {
            lua_pushnil(L); /* cannot find anything */
            return 1;
        }
        init = s;
    }
    ms.L = L;
    ms.matchdepth = MAXCCALLS;
    ms.src_init = s;
    ms.src_end = es;
    ms.p = p;
    ms.p_end = ep;
    /* explicit request or no special characters? */
    if (find && (lua_toboolean(L, 4) || nospecials(p, ep)))
        n = find_plain(&ms, lu_newslice(init, es - init), idx);
    else
        n = find_pattern(&ms, lu_newslice(init, es - init), idx, find);
    if (n) return n;
    lua_pushnil(L); /* not found */
    return 1;
}

static int Lutf8_find(lua_State *L) { return find_aux(L, 1); }
static int Lutf8_match(lua_State *L) { return find_aux(L, 0); }

static int gmatch_aux(lua_State *L) {
    MatchState  ms;
    lu_Slice    sl = check_utf8(L, lua_upvalueindex(1));
    lu_Slice    pl = check_utf8(L, lua_upvalueindex(2));
    const char *s = sl.s, *es = sl.e, *p = pl.s, *ep = pl.e;
    const char *src;
    ms.L = L;
    ms.matchdepth = MAXCCALLS;
    ms.src_init = s;
    ms.src_end = es;
    ms.p_end = ep;
    for (src = s + (size_t)lua_tointeger(L, lua_upvalueindex(3));
         src <= ms.src_end; src = utf8_next(src, ms.src_end)) {
        const char *e;
        ms.level = 0;
        assert(ms.matchdepth == MAXCCALLS);
        if ((e = match(&ms, src, p)) != NULL) {
            lua_Integer newstart = e - s;
            if (e == src)
                newstart++; /* empty match? go at least one position */
            lua_pushinteger(L, newstart);
            lua_replace(L, lua_upvalueindex(3));
            return push_captures(&ms, lu_newslice(src, e - src));
        }
        if (src == ms.src_end) break;
    }
    return 0; /* not found */
}

static int Lutf8_gmatch(lua_State *L) {
    luaL_checkstring(L, 1);
    luaL_checkstring(L, 2);
    lua_settop(L, 2);
    lua_pushinteger(L, 0);
    lua_pushcclosure(L, gmatch_aux, 3);
    return 1;
}

static void add_s(MatchState *ms, luaL_Buffer *b, lu_Slice s) {
    lu_Slice    newsl = to_utf8(ms->L, 3);
    const char *news = newsl.s, *new_end = newsl.e;
    while (news < new_end) {
        utfint ch = 0;
        news = utf8_safe_decode(ms->L, news, &ch);
        if (ch != L_ESC)
            add_utf8char(b, ch);
        else {
            news = utf8_safe_decode(ms->L, news, &ch); /* skip ESC */
            if (!utf8_isdigit(ch)) {
                if (ch != L_ESC)
                    luaL_error(
                            ms->L,
                            "invalid use of " LUA_QL(
                                    "%c") " in replacement string",
                            L_ESC);
                add_utf8char(b, ch);
            } else if (ch == '0')
                luaL_addlstring(b, s.s, s.e - s.s);
            else {
                push_onecapture(ms, ch - '1', s);
                luaL_addvalue(b); /* add capture to accumulated result */
            }
        }
    }
}

static void add_value(MatchState *ms, luaL_Buffer *b, lu_Slice s, int tr) {
    lua_State *L = ms->L;
    int        n;
    switch (tr) {
    case LUA_TFUNCTION:
        lua_pushvalue(L, 3);
        n = push_captures(ms, s);
        lua_call(L, n, 1);
        break;
    case LUA_TTABLE:
        push_onecapture(ms, 0, s);
        lua_gettable(L, 3);
        break;
    default: /* LUA_TNUMBER or LUA_TSTRING */ add_s(ms, b, s); return;
    }
    if (!lua_toboolean(L, -1)) { /* nil or false? */
        lua_pop(L, 1);
        lua_pushlstring(L, s.s, s.e - s.s); /* keep original text */
    } else if (!lua_isstring(L, -1))
        luaL_error(L, "invalid replacement value (a %s)", luaL_typename(L, -1));
    luaL_addvalue(b); /* add result to accumulator */
}

/* Try one gsub step; returns 0 when the end of string is reached. */
static int gsub_one_match(MatchState *ms, luaL_Buffer *b, lu_Slice *src) {
    const char  *s = src->s, *es = src->e, *p = ms->p;
    const char  *e;
    utfint       ch;
    int          tr = ms->tr;
    lua_Integer *pn = ms->pn;
    ms->level = 0;
    assert(ms->matchdepth == MAXCCALLS);
    e = match(ms, s, p);
    if (e) {
        (*pn)++;
        add_value(ms, b, lu_newslice(s, e - s), tr);
    }
    if (e && e > s) /* non empty match? */
        src->s = e; /* skip it */
    else if (s < es) {
        s = utf8_safe_decode(ms->L, s, &ch);
        add_utf8char(b, ch);
        src->s = s;
    } else
        return 0;
    return 1;
}

static int Lutf8_gsub(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *es = sl.e;
    lu_Slice    pl = check_utf8(L, 2);
    const char *p = pl.s, *ep = pl.e;
    int         tr = lua_type(L, 3);
    lua_Integer max_s = luaL_optinteger(L, 4, (es - s) + 1);
    int         anchor = (*p == '^');
    lua_Integer n = 0;
    MatchState  ms;
    luaL_Buffer b;
    luaL_argcheck(
            L,
            tr == LUA_TNUMBER || tr == LUA_TSTRING || tr == LUA_TFUNCTION
                    || tr == LUA_TTABLE,
            3, "string/function/table expected");
    luaL_buffinit(L, &b);
    if (anchor) p++; /* skip anchor character */
    ms.L = L;
    ms.matchdepth = MAXCCALLS;
    ms.src_init = s;
    ms.src_end = es;
    ms.p = p;
    ms.p_end = ep;
    ms.tr = tr;
    ms.pn = &n;
    while (n < max_s) {
        if (!gsub_one_match(&ms, &b, &sl)) break;
        if (anchor) break;
    }
    luaL_addlstring(&b, sl.s, es - sl.s);
    luaL_pushresult(&b);
    lua_pushinteger(L, n); /* number of substitutions */
    return 2;
}

static int Lutf8_isvalid(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    const char *invalid = utf8_invalid_offset(lu_newslice(s, e - s));
    lua_pushboolean(L, invalid == NULL);
    return 1;
}

static int Lutf8_invalidoffset(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;
    const char *orig_s = s;
    lua_Integer offset = luaL_optinteger(L, 2, 0);
    if (offset > 1) {
        offset--;
        s += offset;
        if (s >= e) {
            lua_pushnil(L);
            return 1;
        }
    } else if (offset < 0 && s - e < offset) {
        s = e + offset;
    }
    const char *invalid = utf8_invalid_offset(lu_newslice(s, e - s));
    if (invalid == NULL) {
        lua_pushnil(L);
    } else {
        lua_pushinteger(L, invalid - orig_s + 1);
    }
    return 1;
}

/* Step past one contiguous run of invalid bytes; update *ps and *pinvalid */
static void skip_invalid_run(lu_Slice *s, const char **pinvalid) {
    const char *invalid = *pinvalid;
    const char *e = s->e;
    s->s = invalid;
    while (s->s == invalid) {
        s->s++;
        invalid = utf8_invalid_offset(lu_newslice(s->s, e - s->s));
    }
    *pinvalid = invalid;
}

static int lutf8_clean_replace(lua_State *L, lu_Slice s, lu_Slice r) {
    const char *invalid = utf8_invalid_offset(s);
    const char *e = s.e;
    luaL_Buffer buff;
    luaL_buffinit(L, &buff);
    while (1) {
        /* Invariant: 's' points to first GOOD byte not in output buffer,
         * 'invalid' points to first BAD byte after that */
        luaL_addlstring(&buff, s.s, invalid - s.s);
        luaL_addlstring(&buff, r.s, r.e - r.s);
        /* Replace a contiguous run of bad bytes with a single replacement. */
        skip_invalid_run(&s, &invalid);
        if (invalid == NULL) {
            luaL_addlstring(&buff, s.s, e - s.s);
            luaL_pushresult(&buff);
            lua_pushboolean(L, 0); /* String was not clean */
            return 2;
        }
    }
}

static int Lutf8_clean(lua_State *L) {
    lu_Slice    sl = check_utf8(L, 1);
    const char *s = sl.s, *e = sl.e;

    /* Default replacement string is REPLACEMENT CHARACTER U+FFFD */
    size_t      repl_len;
    const char *r = luaL_optlstring(L, 2, "\xEF\xBF\xBD", &repl_len);

    if (lua_gettop(L) > 1) {
        /* Check if replacement string is valid UTF-8 or not */
        if (utf8_invalid_offset(lu_newslice(r, repl_len)) != NULL) {
            lua_pushstring(L, "replacement string must be valid UTF-8");
            lua_error(L);
        }
    }

    if (utf8_invalid_offset(lu_newslice(s, e - s)) == NULL) {
        lua_settop(L, 1);      /* Return input string without modification */
        lua_pushboolean(L, 1); /* String was clean already */
        return 2;
    }
    return lutf8_clean_replace(
            L, lu_newslice(s, e - s), lu_newslice(r, repl_len));
}

/* Return 0 if this codepoint makes the string not NFC */
static int nfc_check_codepoint(
        utfint ch, nfc_table *entry, utfint starter, unsigned int canon_cls,
        unsigned int prev_canon_cls) {
    if (canon_cls && canon_cls < prev_canon_cls) return 0;
    if (entry && !nfc_check(ch, entry, starter, canon_cls, prev_canon_cls))
        return 0;
    return 1;
}

/* Scan from 's' to 'e'; return 1 if already NFC, else 0 and set *starter_p */
static int nfc_scan(lua_State *L, lu_Slice *v, utfint *st, unsigned int *pc) {
    const char  *p = v->s;
    const char  *e = v->e;
    utfint       ch;
    unsigned int canon_cls;
    while (p < e) {
        const char *new_p = utf8_decode(p, &ch, 1);
        luaL_argcheck(L, (new_p != NULL), 1, "string is not valid UTF-8");
        canon_cls = lookup_canon_cls(ch);
        if (!nfc_check_codepoint(ch, nfc_quickcheck(ch), *st, canon_cls, *pc))
            return 0;
        *pc = canon_cls;
        if (!canon_cls) {
            *st = ch;
            v->s = p;
        }
        p = new_p;
    }
    return 1;
}

static int Lutf8_isnfc(lua_State *L) {
    lu_Slice     sl = check_utf8(L, 1);
    const char  *e = sl.e, *s = sl.s;
    utfint       starter = 0, ch;
    unsigned int prev_canon_cls = 0, canon_cls;

    while (s < e) {
        s = utf8_decode(s, &ch, 1);
        luaL_argcheck(L, (s != NULL), 1, "string is not valid UTF-8");
        if (ch < 0x300) {
            starter = ch; /* Fast path */
            prev_canon_cls = 0;
            continue;
        }
        canon_cls = lookup_canon_cls(ch);
        if (!nfc_check_codepoint(
                    ch, nfc_quickcheck(ch), starter, canon_cls,
                    prev_canon_cls)) {
            lua_pushboolean(L, 0); /* Return false */
            return 1;
        }
        prev_canon_cls = canon_cls;
        if (!canon_cls) starter = ch;
    }

    lua_pushboolean(L, 1); /* Return true */
    return 1;
}

static int Lutf8_normalize_nfc(lua_State *L) {
    lu_Slice     sl = check_utf8(L, 1);
    lu_Slice     scan = sl;
    const char  *e = sl.e, *s = sl.s;
    utfint       starter = 0;
    unsigned int prev_canon_cls = 0;

    /* First scan to see if we can find any problems... if not, we may just
     * return the input string unchanged */
    if (nfc_scan(L, &scan, &starter, &prev_canon_cls)) {
        lua_settop(L, 1);      /* Return input string without modification */
        lua_pushboolean(L, 1); /* String was in normal form already */
        return 2;
    }

    /* We will need to build a new string, this one is not NFC */
    luaL_Buffer buff;
    luaL_buffinit(L, &buff);
    luaL_addlstring(&buff, s, scan.s - s);

    string_to_nfc(L, &buff, lu_newslice(scan.s, e - scan.s));

    luaL_pushresult(&buff);
    lua_pushboolean(L, 0);
    return 2;
}

#define G_NO       0
#define G_BIND     1
#define G_BREAK    2
#define G_CONTINUE 3

typedef struct GraphemeCtx {
    lua_State  *L;
    const char *s, *e, *p, *next_p;
    utfint      ch, next_ch;
} GraphemeCtx;

static int grapheme_ctrl(GraphemeCtx *ctx) {
    if (ctx->ch == '\r') {
        if (ctx->next_ch == '\n') return G_BIND;
        return G_BREAK;
    }
    if (ctx->ch == '\n' || ctx->next_ch == '\r' || ctx->next_ch == '\n')
        return G_BREAK;
    if (find_in_range(cntrl_table, table_size(cntrl_table), ctx->ch)
        && !find_in_range(prepend_table, table_size(prepend_table), ctx->ch)
        && ctx->ch != 0x200D
        && !find_in_range(compose_table, table_size(compose_table), ctx->ch))
        return G_BREAK;
    if (find_in_range(cntrl_table, table_size(cntrl_table), ctx->next_ch)
        && !find_in_range(
                prepend_table, table_size(prepend_table), ctx->next_ch)
        && !find_in_range(
                compose_table, table_size(compose_table), ctx->next_ch))
        return G_BREAK;
    return G_NO;
}

static int grapheme_zwj(GraphemeCtx *ctx) {
    utfint      nextnext_ch;
    const char *probe_ep;
    if (ctx->next_ch != 0x200D) return G_NO;
    if (ctx->next_p < ctx->e
        && find_in_range(
                pictographic_table, table_size(pictographic_table), ctx->ch)) {
        probe_ep = utf8_safe_decode(ctx->L, ctx->next_p, &nextnext_ch);
        if (find_in_range(
                    pictographic_table, table_size(pictographic_table),
                    nextnext_ch)) {
            ctx->p = probe_ep;
            ctx->ch = nextnext_ch;
            return G_CONTINUE;
        }
    }
    return G_BIND;
}

static int grapheme_indic(GraphemeCtx *ctx) {
    utfint      probed_ch;
    const char *probe;
    int         indic_type, saw_linker;
    if (indic_conjunct_type(ctx->ch) != INDIC_CONSONANT) return G_NO;
    probed_ch = ctx->next_ch;
    probe = ctx->next_p;
    indic_type = indic_conjunct_type(probed_ch);
    saw_linker = 0;
    while (indic_type) {
        if (indic_type == INDIC_LINKER) {
            saw_linker = 1;
        } else if (indic_type == INDIC_CONSONANT) {
            if (!saw_linker) break;
            ctx->p = probe;
            ctx->ch = probed_ch;
            return G_CONTINUE;
        }
        if (probe >= ctx->e) break;
        probe = utf8_safe_decode(ctx->L, probe, &probed_ch);
        indic_type = indic_conjunct_type(probed_ch);
    }
    return G_NO;
}

/* Consume extend/ZWJ/pictographic runs after an Extended_Pictographic. */
static void grapheme_extend_scan(GraphemeCtx *ctx) {
    utfint      probed_ch;
    const char *probe = ctx->next_p;
    while (probe < ctx->e) {
        probe = utf8_safe_decode(ctx->L, probe, &probed_ch);
        if (probed_ch == 0x200D) {
            if (probe < ctx->e) {
                probe = utf8_safe_decode(ctx->L, probe, &probed_ch);
                if (find_in_range(
                            pictographic_table, table_size(pictographic_table),
                            probed_ch)) {
                    ctx->next_p = probe;
                    ctx->next_ch = probed_ch;
                }
            }
            break;
        } else if (
                find_in_range(
                        compose_table, table_size(compose_table), probed_ch)
                || (probed_ch >= 0x1F3FB && probed_ch <= 0x1F3FF)) {
            ctx->next_p = probe;
            ctx->next_ch = probed_ch;
        } else {
            break;
        }
    }
}

static int grapheme_hangul(GraphemeCtx *ctx) {
    int hangul1 = hangul_type(ctx->ch);
    int hangul2;
    if (!hangul1) return G_NO;
    hangul2 = hangul_type(ctx->next_ch);
    if (!hangul2) return G_NO;
    if (hangul1 == HANGUL_L) return (hangul2 != HANGUL_T) ? G_BIND : G_NO;
    if (hangul1 == HANGUL_LV || hangul1 == HANGUL_V)
        return (hangul2 == HANGUL_V || hangul2 == HANGUL_T) ? G_BIND : G_NO;
    if (hangul1 == HANGUL_LVT || hangul1 == HANGUL_T)
        return (hangul2 == HANGUL_T) ? G_BIND : G_NO;
    return G_NO;
}

static int grapheme_extend(GraphemeCtx *ctx) {
    if (find_in_range(compose_table, table_size(compose_table), ctx->next_ch)
        || (ctx->next_ch >= 0x1F3FB && ctx->next_ch <= 0x1F3FF)) {
        if (ctx->next_p < ctx->e
            && find_in_range(
                    pictographic_table, table_size(pictographic_table),
                    ctx->ch))
            grapheme_extend_scan(ctx);
        return G_BIND;
    }
    if (find_in_range(
                spacing_mark_table, table_size(spacing_mark_table),
                ctx->next_ch))
        return G_BIND;
    if (find_in_range(prepend_table, table_size(prepend_table), ctx->ch))
        return G_BIND;
    if (ctx->ch >= 0x1F1E6 && ctx->ch <= 0x1F1FF && ctx->next_ch >= 0x1F1E6
        && ctx->next_ch <= 0x1F1FF) {
        ctx->p = ctx->next_p;
        ctx->ch = 0xFFFE;
        return G_CONTINUE;
    }
    return grapheme_hangul(ctx);
}

static void grapheme_next(GraphemeCtx *ctx) {
    int r;
    while (1) {
        ctx->next_p = utf8_safe_decode(ctx->L, ctx->p, &ctx->next_ch);
        r = grapheme_ctrl(ctx);
        if (!r) r = grapheme_zwj(ctx);
        if (!r) r = grapheme_indic(ctx);
        if (!r) r = grapheme_extend(ctx);
        if (r == G_BREAK || r == G_NO) return;
        if (r == G_CONTINUE) continue;
        ctx->p = ctx->next_p;
        ctx->ch = ctx->next_ch;
    }
}

static int iterate_grapheme_indices(lua_State *L) {
    const char *s = luaL_checkstring(L, lua_upvalueindex(1));
    lua_Integer pos = luaL_checkinteger(L, lua_upvalueindex(2));
    lua_Integer end = luaL_checkinteger(L, lua_upvalueindex(3));
    GraphemeCtx ctx;
    if (pos > end) {
        lua_pushnil(L);
        return 1;
    }
    ctx.L = L;
    ctx.s = s;
    ctx.e = s + end;
    ctx.p = utf8_safe_decode(L, s + pos - 1, &ctx.ch);
    grapheme_next(&ctx);
    lua_pushinteger(L, (ctx.p - s) + 1);
    lua_replace(L, lua_upvalueindex(2));
    lua_pushinteger(L, pos);
    lua_pushinteger(L, ctx.p - s);
    return 2;
}

static int Lutf8_grapheme_indices(lua_State *L) {
    size_t      len;
    lua_Integer start, end;
    luaL_checklstring(L, 1, &len);
    start = byte_relat(luaL_optinteger(L, 2, 1), len);
    end = byte_relat(luaL_optinteger(L, 3, len), len);
    luaL_argcheck(L, start >= 1, 2, "out of range");
    luaL_argcheck(L, end <= (lua_Integer)len, 3, "out of range");

    lua_settop(L, 1);
    lua_pushinteger(L, start);
    lua_pushinteger(L, end);
    lua_pushcclosure(L, iterate_grapheme_indices, 3);
    return 1;
}

/* lua module import interface */

#if LUA_VERSION_NUM >= 502
static const char UTF8PATT[] = "[\0-\x7F\xC2-\xF4][\x80-\xBF]*";
#else
static const char UTF8PATT[] = "[%z\1-\x7F\xC2-\xF4][\x80-\xBF]*";
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

    lua_pushlstring(L, UTF8PATT, sizeof(UTF8PATT) - 1);
    lua_setfield(L, -2, "charpattern");

    lua_pushliteral(L, LUTF8_VERSION);
    lua_setfield(L, -2, "version");
    return 1;
}

/* win32cc: flags+='-Wall -Wextra -s -O2 -mdll -DLUA_BUILD_AS_DLL'
 * win32cc: libs+='-llua54.dll' output='lua-utf8.dll'
 * win32cc: run='lua.exe test.lua'
 * maccc: run='lua -- test_compat.lua'
 * maccc: flags+='-g --coverage -bundle -undefined dynamic_lookup'
 * output='lua-utf8.so' */
