#include "leptjson.h"
#include <ctype.h>
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, strtod() */
#include <errno.h>
#include <math.h>

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)

#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')

typedef struct {
    const char* json;
}lept_context;

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_literal
        (lept_context *c, lept_value *v,
         const char *literal, size_t sz,
         char expect_char, int expect_type)
{
    size_t i;
    assert(sz > 0);
    EXPECT(c, literal[0]);
    for (i = 0U; i < sz - 1; ++i)
    {
        if (c->json[i] != literal[i + 1])
        {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += (sz - 1);
    v->type = expect_type;
    return LEPT_PARSE_OK;
}

static int lept_parse_true(lept_context* c, lept_value* v) {
    static const char   literal[] = "true";
    static const size_t sz        = sizeof(literal) - 1;
    return lept_parse_literal(c, v, literal, sz, *literal, LEPT_TRUE);
}

static int lept_parse_false(lept_context* c, lept_value* v) {
    static const char   literal[] = "false";
    static const size_t sz        = sizeof(literal) - 1;
    return lept_parse_literal(c, v, literal, sz, *literal, LEPT_FALSE);
}

static int lept_parse_null(lept_context* c, lept_value* v) {
    static const char   literal[] = "null";
    static const size_t sz        = sizeof(literal) - 1;
    return lept_parse_literal(c, v, literal, sz, *literal, LEPT_NULL);
}

static void lept_parse_digit(lept_context *c)
{
    while (isdigit(*c->json))
    {
        c->json++;
    }
}

static int valid_03(lept_context *c);
static int valid_04(lept_context *c);
static int valid_05(lept_context *c);
static int valid_06(lept_context *c);
static int valid_07(lept_context *c);

static int valid_01(lept_context *c)
{
    if (*c->json == '\0')
    {
        return LEPT_PARSE_OK;
    }
    else if (*c->json == '.')
    {
        c->json++;
        return valid_04(c);
    }
    else if (*c->json == 'e' || *c->json == 'E')
    {
        c->json++;
        return valid_06(c);
    }
    else
    {
        return LEPT_PARSE_ROOT_NOT_SINGULAR;
    }
}

static int valid_02(lept_context *c)
{
    if (*c->json == '0')
    {
        c->json++;
        return valid_01(c);
    }
    else if (isdigit(*c->json))
    {
        c->json++;
        return valid_03(c);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}

static int valid_03(lept_context *c)
{
    lept_parse_digit(c);
    if (*c->json == '\0')
    {
        return LEPT_PARSE_OK;
    }
    else if (*c->json == '.')
    {
        c->json++;
        return valid_04(c);
    }
    else if (*c->json == 'e' || *c->json == 'E')
    {
        c->json++;
        return valid_06(c);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}

static int valid_04(lept_context *c)
{
    if (isdigit(*c->json))
    {
        c->json++;
        return valid_05(c);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}

static int valid_05(lept_context *c)
{
    lept_parse_digit(c);
    if (*c->json == '\0')
    {
        return LEPT_PARSE_OK;
    }
    else if (*c->json == 'e' || *c->json == 'E')
    {
        c->json++;
        return valid_06(c);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}

static int valid_06(lept_context *c)
{
    if (*c->json == '+' || *c->json == '-')
    {
        c->json++;
    }

    if (isdigit(*c->json))
    {
        c->json++;
        return valid_07(c);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}

static int valid_07(lept_context *c)
{
    lept_parse_digit(c);
    if (*c->json == '\0')
    {
        return LEPT_PARSE_OK;
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}

static int valid_number(lept_context *c)
{
    if (*c->json == '0')
    {
        c->json++;
        return valid_01(c);
    }
    else if (*c->json == '-')
    {
        c->json++;
        return valid_02(c);
    }
    else if (isdigit(*c->json))
    {
        c->json++;
        return valid_03(c);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }
}


static int valid_number2(lept_context *c, char **end)
{
    const char *p = c->json;
    if (*p == '-')
        ++p;
    if (*p == '0')
    {
        ++p;
    }
    else if (ISDIGIT1TO9(*p))
    {
        for (p++; ISDIGIT(*p); p++);
    }
    else
    {
        return LEPT_PARSE_INVALID_VALUE;
    }

    if (*p == '.')
    {
        p++;
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }

    if (*p == 'e' || *p == 'E')
    {
        p++;
        if (*p == '+' || *p == '-')
        {
            p++;
        }
        if (!ISDIGIT(*p))
            return LEPT_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++){};
    }

    *end = p;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    char *end;
    int ret;
    lept_context tc;
    tc.json = c->json;
    ret = valid_number2(&tc, &end);
    if (ret != LEPT_PARSE_OK)
    {
        return ret;
    }
    errno = 0;
    v->n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL))
    {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    c->json = end;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 't':  return lept_parse_true(c, v);
        case 'f':  return lept_parse_false(c, v);
        case 'n':  return lept_parse_null(c, v);
        default:   return lept_parse_number(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return ret;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}
