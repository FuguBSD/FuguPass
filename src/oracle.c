/*
 * Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * The record client: one enrollment, one reveal, one canary, and the
 * counters file. oracle.h states the interface and the states.
 *
 * request_at() holds the one request of this file. It derives the
 * client key of the record, draws the ephemeral values, and sends
 * one POST under a given pin secret at a given counter. request()
 * gives it the pin secret of the passphrase and the next counter
 * of the record, and each public function of an ordinary request
 * reaches it that way. canary() calls it twice, and every other
 * path sends one request for one record (ORC-CANARY-7).
 * oracle_revoke() gives it a random pin secret at the counter
 * COUNTER_REVOKE, and it is the one caller that does
 * (ORC-COUNTER-5, ORC-REVOKE-8).
 *
 * canary() carries the two canary enrollments, and
 * oracle_canary_check() is the canary check of one oracle. The
 * index wrap of an oracle takes the canary mask of that oracle, so
 * the wrap rides on the request of the canary and sends none of its
 * own (ORC-CANARY-3, KEY-MASK-7). An enrollment that replaced the
 * mask leaves a fresh index wrap of that oracle, or no wrap file of
 * it (ORC-CANARY-8).
 *
 * The steps come from the other files of the tree. derive.c holds
 * each label, pin.c holds the pin secret, share.c holds the split,
 * envelope.c holds the protocol, http.c holds the transport, seal.c
 * holds the seal, and vault.c holds every path, the one reader and
 * the one writer.
 * This file adds the record: the addresses, the counter, and the
 * order of the steps.
 *
 * The protocol lengths of envelope.h and the derivation length of
 * derive.h are 32 bytes each, and each call gates the length that it
 * takes.
 *
 * Each secret lives in a stack buffer, and each exit path clears it
 * under one goto out (SEC-MEMORY-1). The counters file holds no
 * secret, so the two buffers of it take no clear (ORC-COUNTER-3).
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "derive.h"
#include "envelope.h"
#include "http.h"
#include "oracle.h"
#include "pin.h"
#include "seal.h"
#include "share.h"
#include "vault.h"

/* The two paths that the client appends to a URL (ORC-PROVISION-4). */
#define PATH_GET	"/get_pin"
#define PATH_SET	"/set_pin"

/* One URL of a request: the provisioned URL, a path, and a terminator. */
#define URL_MAX		(VAULT_URL_MAX + sizeof(PATH_SET))

/*
 * The counter of a revocation request (ORC-REVOKE-8). It passes
 * anti-replay against every lower stored counter, and no later
 * request of that record passes it. oracle_revoke() is the one
 * function that sends it, and counter_take() stops every ordinary
 * request at it (ORC-COUNTER-5).
 */
#define COUNTER_REVOKE	UINT32_MAX

/*
 * One record name: 10 digits of a slot, a hyphen, 3 digits of an
 * oracle index, and a terminator. The canary form is shorter
 * (ORC-COUNTER-2).
 */
#define RECORD_MAX	16

/* One line of the counters file: a record name, ": ", a value, and "\n". */
#define COUNTER_LINE	(RECORD_MAX + 13)

/*
 * The bytes of the counters file that this client takes. The file
 * holds one line per record of this machine, so the bound holds
 * about 2400 records.
 */
#define COUNTERS_MAX	65536

/* The state of one pass over the counters file. */
struct counter_state {
	const char	*name;		/* the record of this request */
	char		*out;		/* the lines of the other records */
	size_t		 outsize;
	size_t		 outlen;
	uint32_t	 stored;	/* the counter of this record */
};

static int	ctx_ok(const struct oracle_ctx *, int);
static int	hex_digit(char);
static int	key_bytes(const char *, unsigned char *, size_t);
static int	request_url(const struct vault_oracle *, const char *, char *,
		    size_t);
static int	record_name(uint32_t, int, unsigned int, char *, size_t);
static int	counter_line(const struct vault_line *, void *);
static int	counter_take(const char *, uint32_t, int, unsigned int,
		    uint32_t *);
static int	wrap_path(const struct oracle_ctx *, uint32_t, char *, size_t);
static int	wrap_index_drop(const struct oracle_ctx *);
static int	request_at(const struct oracle_ctx *, uint32_t, int,
		    const unsigned char *, const unsigned char *, uint32_t,
		    unsigned char *);
static int	request(const struct oracle_ctx *, uint32_t, int,
		    const unsigned char *, unsigned char *);
static int	canary(const struct oracle_ctx *, const char *, size_t,
		    const unsigned char *, size_t);

const char *
oracle_state_text(int state)
{
	switch (state) {
	case ORACLE_ESTATUS:
		return "the oracle answers an HTTP error";
	case ORACLE_ETRANSPORT:
		return "the transport fails";
	case ORACLE_EAUTH:
		return "the answer fails the authentication of the oracle";
	case ORACLE_EJUNK:
		return "the answer is junk";
	default:
		return "the request fails";
	}
}

/*
 * ctx_ok(ctx, pass):
 *	0 when the context names one live position of the config, and
 *	-1 for every other context. The oracle index is the 1-based
 *	position of the ordered list, and a retired position holds no
 *	oracle (ORC-PROVISION-5, ORC-PROVISION-9). pass takes 1 for a
 *	request that derives its pin secret from the passphrase, and
 *	0 for a revocation, which takes none (ORC-REVOKE-8).
 */
static int
ctx_ok(const struct oracle_ctx *ctx, int pass)
{
	if (ctx == NULL || ctx->vault == NULL || ctx->config == NULL ||
	    ctx->factor == NULL)
		return -1;
	if (ctx->factorlen != DERIVE_KEYLEN)
		return -1;
	if (pass && (ctx->pass == NULL || ctx->passlen == 0))
		return -1;
	if (ctx->oracle == 0 || ctx->oracle > ctx->config->count)
		return -1;
	if (ctx->config->oracle[ctx->oracle - 1].retired)
		return -1;

	/*
	 * The vault takes one threshold and one ordered set, with
	 * 1 <= k <= n <= 255 (ORC-PROVISION-2). The struct of the
	 * config holds the last bound, and the reader of the file
	 * holds the others (VAULT-CONFIG-6). This gate holds them
	 * again, because a caller can build a config by hand.
	 */
	if (ctx->config->threshold == 0 ||
	    ctx->config->threshold > ctx->config->count)
		return -1;

	/* The round count of the pin secret comes from the config. */
	if (ctx->config->rounds == 0)
		return -1;
	return 0;
}

/*
 * hex_digit(c):
 *	The value of the lowercase hex character c, and -1 for every
 *	other character.
 */
static int
hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * key_bytes(hex, out, outlen):
 *	The outlen bytes of the lowercase hex string at hex, to out.
 *	The static public key of a position is hex in the config file
 *	(ORC-PROVISION-1), and the envelope takes the bytes of it. A
 *	string of another length gives -1.
 */
static int
key_bytes(const char *hex, unsigned char *out, size_t outlen)
{
	size_t	 i;
	int	 hi, lo;

	if (strlen(hex) != 2 * outlen)
		return -1;
	for (i = 0; i < outlen; i++) {
		hi = hex_digit(hex[2 * i]);
		lo = hex_digit(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return 0;
}

/*
 * request_url(pos, path, out, outlen):
 *	The URL of one request of the position pos, to the outlen
 *	bytes at out. path is PATH_GET or PATH_SET. A provisioned URL
 *	must not end with a slash, and this gate rejects one
 *	(ORC-PROVISION-4).
 */
static int
request_url(const struct vault_oracle *pos, const char *path, char *out,
    size_t outlen)
{
	size_t	 urllen;
	int	 n;

	urllen = strlen(pos->url);
	if (urllen == 0 || pos->url[urllen - 1] == '/')
		return -1;
	n = snprintf(out, outlen, "%s%s", pos->url, path);
	if (n < 0 || (size_t)n >= outlen)
		return -1;
	return 0;
}

/*
 * record_name(slot, canary, oracle, out, outlen):
 *	The record name of one record, to the outlen bytes at out.
 *	The name is <e>-<i>, and the canary form is canary-<i>
 *	(ORC-COUNTER-2, VAULT-FORMAT). A canary record takes no slot
 *	index, so the call steps over slot for it.
 */
static int
record_name(uint32_t slot, int canary, unsigned int oracle, char *out,
    size_t outlen)
{
	int	 n;

	if (canary)
		n = snprintf(out, outlen, "canary-%u", oracle);
	else
		n = snprintf(out, outlen, "%" PRIu32 "-%u", slot, oracle);
	if (n < 0 || (size_t)n >= outlen)
		return -1;
	return 0;
}

/*
 * counter_line(line, arg):
 *	Take one line of the counters file to the state at arg. The
 *	line of the record of this request gives the stored counter,
 *	and every other line goes to the new file.
 *
 *	The scanner holds the form of each name and of each value, so
 *	this function writes the line again from the parsed parts
 *	(VAULT-FORMAT-7). The scanner also rejects a second line of
 *	one record, so the stored counter takes one line
 *	(VAULT-FORMAT-8).
 */
static int
counter_line(const struct vault_line *line, void *arg)
{
	struct counter_state	*st = arg;
	char			 name[RECORD_MAX];
	uint32_t		 value;
	int			 canary, n;

	canary = (line->field->form == VAULT_NAME_ORACLE);
	if (record_name(line->slot, canary, line->oracle, name,
	    sizeof(name)) != 0)
		return -1;
	if (vault_number(line->value, line->valuelen, VAULT_COUNTER_MAX,
	    &value) != 0)
		return -1;
	if (strcmp(name, st->name) == 0) {
		st->stored = value;
		return 0;
	}
	n = snprintf(&st->out[st->outlen], st->outsize - st->outlen,
	    "%s: %" PRIu32 "\n", name, value);
	if (n < 0 || (size_t)n >= st->outsize - st->outlen)
		return -1;
	st->outlen += (size_t)n;
	return 0;
}

/*
 * counter_take(vault, slot, canary, oracle, out):
 *	The counter of one request, to out, and the counters file
 *	with that value. The counter is
 *	max(wall-clock Unix seconds, stored + 1) (ORC-COUNTER-1).
 *
 *	The wall-clock term re-establishes a valid counter after the
 *	loss of the file, and it passes the stale stored counter of
 *	an old copy (ORC-COUNTER-3, ORC-COUNTER-4). The write comes
 *	before the request, so a crash after the request never sends
 *	this value again (ORC-COUNTER-2).
 *
 *	No ordinary request sends the value COUNTER_REVOKE, and the
 *	call stops at that value. A revocation is the one request
 *	that sends it, and oracle_revoke() takes no counter from
 *	this call (ORC-COUNTER-5, ORC-REVOKE-8). The Unix-seconds
 *	term stays below that value until 2106.
 */
static int
counter_take(const char *vault, uint32_t slot, int canary,
    unsigned int oracle, uint32_t *out)
{
	struct counter_state	 st;
	char			 name[RECORD_MAX], path[PATH_MAX];
	char			*lines = NULL, *text = NULL;
	time_t			 now;
	uint64_t		 next;
	size_t			 textlen = 0;
	int			 n, rv = -1;

	if (record_name(slot, canary, oracle, name, sizeof(name)) != 0 ||
	    vault_path(path, sizeof(path), vault, VAULT_FILE_COUNTERS,
	    NULL) != 0)
		return -1;
	if ((text = malloc(COUNTERS_MAX + 1)) == NULL ||
	    (lines = malloc(COUNTERS_MAX + COUNTER_LINE)) == NULL)
		goto out;

	memset(&st, 0, sizeof(st));
	st.name = name;
	st.out = lines;
	st.outsize = COUNTERS_MAX + COUNTER_LINE;
	if (vault_read(path, (unsigned char *)text, COUNTERS_MAX + 1,
	    &textlen) != 0 || textlen > COUNTERS_MAX)
		goto out;
	if (textlen != 0 && vault_scan(text, textlen, vault_counters_fields,
	    counter_line, &st) != 0)
		goto out;

	if ((now = time(NULL)) == (time_t)-1 || now < 0)
		goto out;
	next = (uint64_t)now;
	if (next < (uint64_t)st.stored + 1)
		next = (uint64_t)st.stored + 1;
	if (next >= COUNTER_REVOKE)
		goto out;

	n = snprintf(&lines[st.outlen], st.outsize - st.outlen,
	    "%s: %" PRIu64 "\n", name, next);
	if (n < 0 || (size_t)n >= st.outsize - st.outlen)
		goto out;
	st.outlen += (size_t)n;
	if (vault_write(path, (const unsigned char *)lines, st.outlen) != 0)
		goto out;
	*out = (uint32_t)next;
	rv = 0;
out:
	free(lines);
	free(text);
	return rv;
}

/*
 * wrap_path(ctx, slot, out, outlen):
 *	The path of the wrap file of the record of the slot index
 *	slot at the oracle of ctx, to the outlen bytes at out. The
 *	wrap lives in the machine-local set (KEY-MASK-4,
 *	VAULT-LAYOUT-4).
 */
static int
wrap_path(const struct oracle_ctx *ctx, uint32_t slot, char *out,
    size_t outlen)
{
	struct vault_at	 at;

	memset(&at, 0, sizeof(at));
	at.slot = slot;
	at.oracle = ctx->oracle;
	return vault_path(out, outlen, ctx->vault, VAULT_FILE_WRAP, &at);
}

/*
 * wrap_index_drop(ctx):
 *	Remove this machine's index wrap file of the oracle of ctx
 *	(VAULT-LAYOUT-4). A canary enrollment replaced the canary
 *	mask of that oracle, so the wrap is dead, and the absent
 *	file is the detectable state of it (ORC-CANARY-8).
 *
 *	An absent file gives 0, and a removal that fails gives -1.
 */
static int
wrap_index_drop(const struct oracle_ctx *ctx)
{
	struct vault_at	 at;
	char		 path[PATH_MAX];

	memset(&at, 0, sizeof(at));
	at.oracle = ctx->oracle;
	if (vault_path(path, sizeof(path), ctx->vault, VAULT_FILE_WRAP_INDEX,
	    &at) != 0)
		return -1;
	if (unlink(path) == -1 && errno != ENOENT)
		return -1;
	return 0;
}

/*
 * request_at(ctx, slot, canary, entropy, pin, counter, mask):
 *	One request of one record, under the pin secret of
 *	PIN_SECRETLEN bytes at pin and at the counter value counter,
 *	and the mask of the answer to the ENVELOPE_MASKLEN bytes at
 *	mask. canary takes the canary record of the oracle in place
 *	of the record of the slot index slot (ORC-RECORDS-1,
 *	ORC-RECORDS-2).
 *
 *	entropy holds the ENVELOPE_ENTROPYLEN fresh bytes of a
 *	set_pin request, and a NULL entropy makes a get_pin request.
 *	The two operations take the two paths of the URL
 *	(ORC-CONFORM-2, ORC-PROVISION-4).
 *
 *	The client key of a record takes the device factor alone, so
 *	no passphrase enters it (KEY-CLIENT-1, KEY-CLIENT-4). Each
 *	record holds its own key, so the oracle sees an independent
 *	client (ORC-RECORDS-3). The pin and the counter come from
 *	the caller: request() gives the pin of the passphrase and
 *	the next counter of the record, and oracle_revoke() gives a
 *	random pin at COUNTER_REVOKE. This function reads no
 *	counters file, and it writes none.
 *
 *	The call gives 0, or one of the four states of oracle.h. A
 *	failure after the URL gate and the key gate clears mask, and
 *	each caller clears mask as well. The public function of the
 *	call holds the gate of the context, so this function reads
 *	ctx directly.
 */
static int
request_at(const struct oracle_ctx *ctx, uint32_t slot, int canary,
    const unsigned char *entropy, const unsigned char *pin, uint32_t counter,
    unsigned char *mask)
{
	const struct vault_oracle	*pos;
	unsigned char			 body[ENVELOPE_RESPONSE_LEN];
	unsigned char			 req[ENVELOPE_REQUEST_MAX];
	unsigned char			 pub[ENVELOPE_PUBKEYLEN];
	unsigned char			 client[DERIVE_KEYLEN];
	unsigned char			 ckepriv[ENVELOPE_KEYLEN];
	unsigned char			 iv[ENVELOPE_IVLEN];
	char				 url[URL_MAX];
	size_t				 bodylen = 0, reqlen = 0;
	int				 n, status = 0, rv = -1;

	pos = &ctx->config->oracle[ctx->oracle - 1];
	if (request_url(pos, entropy == NULL ? PATH_GET : PATH_SET, url,
	    sizeof(url)) != 0)
		return -1;
	if (key_bytes(pos->key, pub, sizeof(pub)) != 0)
		return -1;

	if (canary)
		n = derive_client_key_canary(ctx->factor, ctx->factorlen,
		    ctx->oracle, client, sizeof(client));
	else
		n = derive_client_key(ctx->factor, ctx->factorlen, ctx->oracle,
		    slot, client, sizeof(client));
	if (n != 0)
		goto out;

	/*
	 * Every request draws a fresh keypair and a fresh IV
	 * (ORC-CONFORM-5, SEC-ENTROPY-4). The caller of a set_pin
	 * draws the entropy of the payload.
	 */
	envelope_draw(ckepriv, iv);
	if (envelope_request(pub, ckepriv, iv, counter, client, pin, entropy,
	    req, sizeof(req), &reqlen) != 0)
		goto out;

	/*
	 * http.c reports the HTTP error and the transport failure,
	 * and envelope.c reports the authentication failure. Each one
	 * takes its own state of oracle.h (ORC-REVEAL-6,
	 * ORC-REVEAL-8).
	 */
	rv = http_post(url, req, reqlen, body, sizeof(body), &bodylen,
	    &status);
	if (rv == HTTP_ESTATUS) {
		rv = ORACLE_ESTATUS;
		goto out;
	}
	if (rv != 0) {
		rv = ORACLE_ETRANSPORT;
		goto out;
	}
	rv = envelope_response(pub, ckepriv, counter, body, bodylen, mask,
	    ENVELOPE_MASKLEN);
	if (rv == ENVELOPE_EAUTH)
		rv = ORACLE_EAUTH;
	else if (rv != 0)
		rv = -1;
out:
	explicit_bzero(client, sizeof(client));
	explicit_bzero(ckepriv, sizeof(ckepriv));
	explicit_bzero(iv, sizeof(iv));
	explicit_bzero(req, sizeof(req));
	explicit_bzero(body, sizeof(body));
	if (rv != 0)
		explicit_bzero(mask, ENVELOPE_MASKLEN);
	return rv;
}

/*
 * request(ctx, slot, canary, entropy, mask):
 *	One ordinary request of one record: request_at() under the
 *	pin secret of the passphrase, at the next counter of the
 *	record. The passphrase enters the request as the pin secret
 *	alone (ORC-CONFORM-3, KEY-PIN-3), and each record holds its
 *	own salt (KEY-PIN-2). counter_take() gives the counter, and
 *	it persists that value before the send (ORC-COUNTER-1,
 *	ORC-COUNTER-2). It stops at COUNTER_REVOKE, so no ordinary
 *	request sends that value (ORC-COUNTER-5).
 *
 *	The call gives the value of request_at(), and -1 for a
 *	failure before the request. A failure clears mask.
 */
static int
request(const struct oracle_ctx *ctx, uint32_t slot, int canary,
    const unsigned char *entropy, unsigned char *mask)
{
	unsigned char	 salt[DERIVE_KEYLEN];
	unsigned char	 pin[PIN_SECRETLEN];
	uint32_t	 counter;
	int		 n, rv = -1;

	if (canary)
		n = derive_pin_salt_canary(ctx->factor, ctx->factorlen,
		    ctx->oracle, salt, sizeof(salt));
	else
		n = derive_pin_salt(ctx->factor, ctx->factorlen, ctx->oracle,
		    slot, salt, sizeof(salt));
	if (n != 0)
		goto out;
	if (pin_secret(ctx->pass, ctx->passlen, salt, sizeof(salt),
	    ctx->config->rounds, pin, sizeof(pin)) != 0)
		goto out;
	if (counter_take(ctx->vault, slot, canary, ctx->oracle, &counter) != 0)
		goto out;
	rv = request_at(ctx, slot, canary, entropy, pin, counter, mask);
out:
	explicit_bzero(salt, sizeof(salt));
	explicit_bzero(pin, sizeof(pin));
	if (rv != 0)
		explicit_bzero(mask, ENVELOPE_MASKLEN);
	return rv;
}

int
oracle_enroll(const struct oracle_ctx *ctx, uint32_t slot,
    const unsigned char *key, size_t keylen)
{
	unsigned char	 entropy[ENVELOPE_ENTROPYLEN];
	unsigned char	 mask[ENVELOPE_MASKLEN];
	unsigned char	 wrapkey[DERIVE_KEYLEN];
	unsigned char	 wrap[DERIVE_KEYLEN];
	char		 path[PATH_MAX];
	size_t		 i;
	int		 rv;

	if (ctx_ok(ctx, 1) != 0 || key == NULL || keylen != DERIVE_KEYLEN ||
	    slot > VAULT_SLOT_MAX)
		return -1;

	/*
	 * Every set_pin request carries 32 fresh bytes of
	 * arc4random(3) (ORC-CONFORM-5, SEC-ENTROPY-4). The service
	 * mixes them into the key material that it stores.
	 */
	arc4random_buf(entropy, sizeof(entropy));
	if ((rv = request(ctx, slot, 0, entropy, mask)) != 0)
		goto out;

	/*
	 * A set_pin failure carries an HTTP error status, and the
	 * state above holds it (ORC-ENROLL-2). The wrap therefore
	 * follows a proven enrollment.
	 */
	rv = -1;
	if (derive_wrap_key(mask, sizeof(mask), ctx->oracle, slot, wrapkey,
	    sizeof(wrapkey)) != 0)
		goto out;

	/*
	 * The share re-derives from K_e at the threshold of the
	 * vault, and it never persists (KEY-SHARE-5, KEY-SHARE-8).
	 * The wrap is c_ei = share(K_e, i) XOR wk_ei (KEY-MASK-4).
	 */
	if (share_split(key, keylen, ctx->config->threshold, ctx->oracle,
	    wrap, sizeof(wrap)) != 0)
		goto out;
	for (i = 0; i < sizeof(wrap); i++)
		wrap[i] ^= wrapkey[i];

	if (wrap_path(ctx, slot, path, sizeof(path)) != 0)
		goto out;
	if (vault_write(path, wrap, sizeof(wrap)) != 0)
		goto out;
	rv = 0;
out:
	/*
	 * The mask and the share leave memory here (ORC-ENROLL-3).
	 * The client must not store a mask (KEY-MASK-2), and the
	 * caller erases K_e after its last use (SEC-MEMORY-6).
	 */
	explicit_bzero(entropy, sizeof(entropy));
	explicit_bzero(mask, sizeof(mask));
	explicit_bzero(wrapkey, sizeof(wrapkey));
	explicit_bzero(wrap, sizeof(wrap));
	return rv;
}

int
oracle_reveal(const struct oracle_ctx *ctx, uint32_t slot, unsigned char *out,
    size_t outlen, unsigned char *maskout)
{
	unsigned char	 mask[ENVELOPE_MASKLEN];
	unsigned char	 wrapkey[DERIVE_KEYLEN];
	unsigned char	 wrap[DERIVE_KEYLEN + 1];
	char		 path[PATH_MAX];
	size_t		 i, wraplen = 0;
	int		 rv;

	if (ctx_ok(ctx, 1) != 0 || out == NULL || outlen != DERIVE_KEYLEN ||
	    slot > VAULT_SLOT_MAX)
		return -1;
	if ((rv = request(ctx, slot, 0, NULL, mask)) != 0)
		goto out;

	/*
	 * The mask leaves this call for the mask-stability test
	 * alone, and that test clears the buffer (TEST-MASK-1,
	 * SEC-MEMORY-1).
	 */
	if (maskout != NULL)
		memcpy(maskout, mask, sizeof(mask));

	/*
	 * The unmask is
	 * share(K_e, i) = c_ei XOR f(s_ei, "fugupass/v1/wrap" || i/e)
	 * (ORC-REVEAL-3, KEY-MASK-3). A junk answer gives a wrong
	 * mask, and the share of it fails the decrypt of the caller
	 * (ORC-REVEAL-4).
	 */
	rv = -1;
	if (derive_wrap_key(mask, sizeof(mask), ctx->oracle, slot, wrapkey,
	    sizeof(wrapkey)) != 0)
		goto out;
	if (wrap_path(ctx, slot, path, sizeof(path)) != 0)
		goto out;

	/* The buffer takes one byte more, so a longer file fails. */
	if (vault_read(path, wrap, sizeof(wrap), &wraplen) != 0 ||
	    wraplen != DERIVE_KEYLEN)
		goto out;
	for (i = 0; i < outlen; i++)
		out[i] = wrap[i] ^ wrapkey[i];
	rv = 0;
out:
	explicit_bzero(mask, sizeof(mask));
	explicit_bzero(wrapkey, sizeof(wrapkey));
	explicit_bzero(wrap, sizeof(wrap));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}

/*
 * canary(ctx, again, againlen, idxkey, idxkeylen):
 *	One canary enrollment of the oracle of ctx, and the index
 *	wrap of that oracle when idxkey holds K_idx. A NULL idxkey
 *	writes no index wrap. The two public functions of this file
 *	hold the gate of each argument.
 *
 *	The set_pin of the enrollment kills this machine's index
 *	wrap of the oracle, so a path that writes no fresh wrap
 *	removes the wrap file (ORC-CANARY-8).
 */
static int
canary(const struct oracle_ctx *ctx, const char *again, size_t againlen,
    const unsigned char *idxkey, size_t idxkeylen)
{
	struct vault_at	 at;
	unsigned char	 entropy[ENVELOPE_ENTROPYLEN];
	unsigned char	 mask[ENVELOPE_MASKLEN];
	unsigned char	 round[ENVELOPE_MASKLEN];
	unsigned char	 sealkey[DERIVE_KEYLEN];
	unsigned char	 wrapkey[DERIVE_KEYLEN];
	unsigned char	 wrap[DERIVE_KEYLEN];
	unsigned char	 check[ORACLE_CHECKLEN];
	unsigned char	 sealed[ORACLE_CHECKLEN + SEAL_OVERHEAD];
	char		 path[PATH_MAX];
	size_t		 i;
	int		 enrolled = 0, wrapped = 0, rv;

	if (ctx_ok(ctx, 1) != 0 || again == NULL)
		return -1;

	/*
	 * A canary enrollment takes two reads of the passphrase, and
	 * a mismatch stops it (ORC-CANARY-6). The comparison runs in
	 * constant time (SEC-MEMORY-2).
	 */
	if (againlen != ctx->passlen ||
	    timingsafe_bcmp(again, ctx->pass, againlen) != 0)
		return -1;

	arc4random_buf(entropy, sizeof(entropy));
	if ((rv = request(ctx, 0, 1, entropy, mask)) != 0)
		goto out;

	/*
	 * The set_pin replaced the canary mask of the oracle, so
	 * this machine's index wrap of it is dead from here on
	 * (ORC-CANARY-8).
	 */
	enrolled = 1;

	/*
	 * One immediate get_pin proves that the fresh record answers
	 * with the enrolled mask (ORC-CANARY-7). Another answer is
	 * junk, and this file sees the cause here.
	 */
	if ((rv = request(ctx, 0, 1, NULL, round)) != 0)
		goto out;
	if (timingsafe_bcmp(round, mask, sizeof(mask)) != 0) {
		rv = ORACLE_EJUNK;
		goto out;
	}

	/*
	 * The canary check value is a fixed constant of 32 zero
	 * bytes, and the seal key is the canary check seal key of
	 * this oracle (ORC-CANARY-2, KEY-MASK-5). The seal goes to
	 * the machine-local set (ORC-CANARY-11, VAULT-LAYOUT-4).
	 */
	rv = -1;
	memset(check, 0, sizeof(check));
	if (derive_canary_check_key(mask, sizeof(mask), ctx->oracle, sealkey,
	    sizeof(sealkey)) != 0)
		goto out;
	memset(&at, 0, sizeof(at));
	at.oracle = ctx->oracle;
	if (vault_path(path, sizeof(path), ctx->vault, VAULT_FILE_CANARY,
	    &at) != 0)
		goto out;
	if (vault_seal_write(path, sealkey, sizeof(sealkey), check,
	    sizeof(check), sealed, sizeof(sealed)) != 0)
		goto out;
	if (idxkey == NULL) {
		rv = 0;
		goto out;
	}

	/*
	 * The index wrap of this oracle is
	 * c_idx_i = share(K_idx, i) XOR
	 * f(s_canary_i, "fugupass/v1/wrap-index" || i) (KEY-MASK-7).
	 * The fresh canary mask of the enrollment above carries it,
	 * so the wrap needs no second request (ORC-CANARY-3).
	 */
	if (derive_index_wrap_key(mask, sizeof(mask), ctx->oracle, wrapkey,
	    sizeof(wrapkey)) != 0)
		goto out;
	if (share_split(idxkey, idxkeylen, ctx->config->threshold, ctx->oracle,
	    wrap, sizeof(wrap)) != 0)
		goto out;
	for (i = 0; i < sizeof(wrap); i++)
		wrap[i] ^= wrapkey[i];

	memset(&at, 0, sizeof(at));
	at.oracle = ctx->oracle;
	if (vault_path(path, sizeof(path), ctx->vault, VAULT_FILE_WRAP_INDEX,
	    &at) != 0)
		goto out;
	if (vault_write(path, wrap, sizeof(wrap)) != 0)
		goto out;
	wrapped = 1;
	rv = 0;
out:
	/*
	 * The canary check value is a public constant, and the seal
	 * of it goes to disk. The two buffers therefore take no
	 * clear.
	 */
	explicit_bzero(entropy, sizeof(entropy));
	explicit_bzero(mask, sizeof(mask));
	explicit_bzero(round, sizeof(round));
	explicit_bzero(sealkey, sizeof(sealkey));
	explicit_bzero(wrapkey, sizeof(wrapkey));
	explicit_bzero(wrap, sizeof(wrap));

	/*
	 * The fresh canary mask killed this machine's index wrap of
	 * the oracle. The write above replaced that wrap, and every
	 * other path takes the file away, so a dead wrap stays
	 * detectable (ORC-CANARY-8). A stale file that stays is a
	 * failure of the call.
	 */
	if (enrolled && !wrapped && wrap_index_drop(ctx) != 0 && rv == 0)
		rv = -1;
	return rv;
}

int
oracle_canary_enroll(const struct oracle_ctx *ctx, const char *again,
    size_t againlen)
{
	return canary(ctx, again, againlen, NULL, 0);
}

int
oracle_canary_index(const struct oracle_ctx *ctx, const char *again,
    size_t againlen, const unsigned char *idxkey, size_t idxkeylen)
{
	if (idxkey == NULL || idxkeylen != DERIVE_KEYLEN)
		return -1;
	return canary(ctx, again, againlen, idxkey, idxkeylen);
}

int
oracle_canary_check(const struct oracle_ctx *ctx, const unsigned char *idxkey,
    size_t idxkeylen, unsigned char *share, size_t sharelen, int *live)
{
	struct vault_at	 at;
	unsigned char	 mask[ENVELOPE_MASKLEN];
	unsigned char	 sealkey[DERIVE_KEYLEN];
	unsigned char	 wrapkey[DERIVE_KEYLEN];
	unsigned char	 wrap[DERIVE_KEYLEN + 1];
	unsigned char	 check[ORACLE_CHECKLEN];
	unsigned char	 zero[ORACLE_CHECKLEN];
	unsigned char	 sealed[ORACLE_CHECKLEN + SEAL_OVERHEAD + 1];
	char		 path[PATH_MAX];
	size_t		 i, len = 0;
	int		 rv;

	if (ctx_ok(ctx, 1) != 0 || share == NULL || sharelen != DERIVE_KEYLEN ||
	    live == NULL)
		return -1;
	if (idxkey != NULL && idxkeylen != DERIVE_KEYLEN)
		return -1;
	*live = 0;

	/* The canary record takes no slot index (ORC-RECORDS-2). */
	if ((rv = request(ctx, 0, 1, NULL, mask)) != 0)
		goto out;

	/*
	 * The canary check value of this oracle seals under
	 * f(s_canary_i, "fugupass/v1/canary-check" || i), and a
	 * wrong mask opens nothing (ORC-CANARY-2, KEY-MASK-5). The
	 * open of the seal and the comparison of the plaintext are
	 * the verification of the passphrase (ORC-CANARY-1).
	 */
	rv = -1;
	if (derive_canary_check_key(mask, sizeof(mask), ctx->oracle, sealkey,
	    sizeof(sealkey)) != 0)
		goto out;
	memset(&at, 0, sizeof(at));
	at.oracle = ctx->oracle;
	if (vault_path(path, sizeof(path), ctx->vault, VAULT_FILE_CANARY,
	    &at) != 0)
		goto out;

	/* The buffer takes one byte more, so a longer file fails. */
	if (vault_read(path, sealed, sizeof(sealed), &len) != 0 ||
	    len != ORACLE_CHECKLEN + SEAL_OVERHEAD)
		goto out;
	if (seal_open(sealkey, sizeof(sealkey), sealed, len, check,
	    sizeof(check)) != 0) {
		rv = ORACLE_EJUNK;
		goto out;
	}

	/*
	 * The check value is 32 zero bytes, and the comparison of it
	 * holds no branch on the plaintext (ORC-CANARY-2,
	 * SEC-MEMORY-2).
	 */
	memset(zero, 0, sizeof(zero));
	if (timingsafe_bcmp(check, zero, sizeof(check)) != 0) {
		rv = ORACLE_EJUNK;
		goto out;
	}

	/*
	 * The canary mask of this request also unwraps this
	 * machine's index share of the oracle, so the index opens
	 * with no request of its own (ORC-CANARY-3, KEY-MASK-7).
	 */
	rv = -1;
	memset(&at, 0, sizeof(at));
	at.oracle = ctx->oracle;
	if (vault_path(path, sizeof(path), ctx->vault, VAULT_FILE_WRAP_INDEX,
	    &at) != 0)
		goto out;
	if (derive_index_wrap_key(mask, sizeof(mask), ctx->oracle, wrapkey,
	    sizeof(wrapkey)) != 0)
		goto out;
	if (vault_read(path, wrap, sizeof(wrap), &len) != 0)
		goto out;
	if (len == DERIVE_KEYLEN) {
		for (i = 0; i < sharelen; i++)
			share[i] = wrap[i] ^ wrapkey[i];
		*live = 1;
		rv = 0;
		goto out;
	}

	/*
	 * An absent wrap is the dead state of ORC-CANARY-8, and a
	 * file of each other length is a failure of this machine.
	 */
	if (len != 0)
		goto out;
	if (idxkey == NULL) {
		rv = 0;
		goto out;
	}

	/*
	 * The heal of a dead wrap: share(K_idx, i) re-derives from
	 * K_idx, and the fresh canary mask wraps it again
	 * (ORC-CANARY-8, KEY-SHARE-5, KEY-MASK-7).
	 */
	if (share_split(idxkey, idxkeylen, ctx->config->threshold, ctx->oracle,
	    share, sharelen) != 0)
		goto out;
	for (i = 0; i < sharelen; i++)
		wrap[i] = share[i] ^ wrapkey[i];
	if (vault_write(path, wrap, DERIVE_KEYLEN) != 0)
		goto out;
	*live = 1;
	rv = 0;
out:
	/*
	 * The mask, the two derived keys and the wrap leave memory
	 * here (KEY-MASK-2, SEC-MEMORY-1). The check value is a
	 * public constant, and the seal of it sits on disk, so the
	 * two buffers of them take no clear.
	 */
	explicit_bzero(mask, sizeof(mask));
	explicit_bzero(sealkey, sizeof(sealkey));
	explicit_bzero(wrapkey, sizeof(wrapkey));
	explicit_bzero(wrap, sizeof(wrap));
	if (rv != 0 || *live == 0)
		explicit_bzero(share, sharelen);
	return rv;
}

int
oracle_revoke(const struct oracle_ctx *ctx, uint32_t slot, int canary,
    int replace)
{
	unsigned char	 entropy[ENVELOPE_ENTROPYLEN];
	unsigned char	 pin[PIN_SECRETLEN];
	unsigned char	 mask[ENVELOPE_MASKLEN];
	int		 rv;

	if (ctx_ok(ctx, 0) != 0 || slot > VAULT_SLOT_MAX)
		return -1;

	/*
	 * The pin secret of a revocation is random, so the attempt
	 * is wrong, and the owner types no passphrase of the revoked
	 * machine (ORC-REVOKE-3). A replacement carries the fresh
	 * entropy of every set_pin (ORC-CONFORM-5). Both values are
	 * request ephemerals, and no file stores one (SEC-ENTROPY-4).
	 */
	arc4random_buf(pin, sizeof(pin));
	arc4random_buf(entropy, sizeof(entropy));
	rv = request_at(ctx, slot, canary, replace ? entropy : NULL, pin,
	    COUNTER_REVOKE, mask);

	/*
	 * The answer of a lock is junk, and the answer of a
	 * replacement is a mask that no machine wraps. Neither one
	 * leaves this call (KEY-MASK-2).
	 */
	explicit_bzero(entropy, sizeof(entropy));
	explicit_bzero(pin, sizeof(pin));
	explicit_bzero(mask, sizeof(mask));
	return rv;
}
