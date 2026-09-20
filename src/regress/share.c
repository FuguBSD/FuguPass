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
 * The known-answer tests of the custody layer (TEST-SPLIT-4,
 * TEST-KAT-4). The parts are the field arithmetic, the share split,
 * the reconstruction, the rejection gates, the client keys, the
 * machine name gate, the device factor, the pin secret, and the wrap
 * keys.
 * tests/vectors/share.h and tests/vectors/derive.h hold the vectors,
 * and every test reads them from there. A test needs no network and
 * no oracle (TEST-SPLIT-6).
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the test, the value and the vector to the standard
 * error, and the program exits 1. Every test runs on each run, so
 * one run reports every wrong value.
 *
 * The values of the tests are public constants of the tests, so this
 * file holds no secret and clears nothing.
 */

#include <sys/param.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>

#include "derive.h"
#include "pin.h"
#include "share.h"

/*
 * The vectors, one directory below tests. Two files carry the name
 * share.h, and two files carry the name derive.h: the interface of a
 * source, and the vectors of that source. The includes above take
 * the interfaces, and the includes below carry the directory name,
 * which the source directory does not hold. No order of the search
 * path can exchange the two files of a name.
 */
#include "vectors/derive.h"
#include "vectors/share.h"

/*
 * Each of the four files sets a guard of its own, and every one of
 * them must enter this file. A build that reaches a wrong file stops
 * here.
 */
#if !defined(SHARE_H) || !defined(VECTORS_SHARE_H)
#error an include of share.c reached the wrong share.h
#endif
#if !defined(DERIVE_H) || !defined(VECTORS_DERIVE_H)
#error an include of share.c reached the wrong derive.h
#endif

/* The highest threshold of the vectors, and the longest index set. */
#define SET_MAX		3

/* The name of one test in a message, with the terminator. */
#define NAMELEN		80

/* The products of the field: a, b, and the product of them. */
static const unsigned char	mul[KAT_SHARE_MUL_COUNT][3] = KAT_SHARE_MUL;

/* The inverses of the field: a, and the inverse of a. */
static const unsigned char	inv[KAT_SHARE_INV_COUNT][2] = KAT_SHARE_INV;

/* The shares of one threshold, for the oracle indexes 1 to 5. */
static const char *const	share_k1[KAT_SHARE_ORACLES] = KAT_SHARE_K1;
static const char *const	share_k2[KAT_SHARE_ORACLES] = KAT_SHARE_K2;
static const char *const	share_k3[KAT_SHARE_ORACLES] = KAT_SHARE_K3;

/*
 * The index set that reconstructs the secret at one threshold. The
 * bound of each array is the threshold, so a set of another count
 * stops the build or fails a test.
 */
static const unsigned int	set_k1[1] = KAT_SHARE_SET_K1;
static const unsigned int	set_k2[2] = KAT_SHARE_SET_K2;
static const unsigned int	set_k3[3] = KAT_SHARE_SET_K3;

/*
 * The thresholds of the vectors. Each case holds the shares of the
 * oracle indexes 1 to KAT_SHARE_ORACLES, and the index set of the
 * reconstruction. The count of the set is the threshold.
 */
static const struct {
	unsigned int		 threshold;
	const char *const	*share;
	const unsigned int	*set;
} thresholds[] = {
	{ 1, share_k1, set_k1 },
	{ 2, share_k2, set_k2 },
	{ 3, share_k3, set_k3 },
};

/*
 * hexdigit(c):
 *	The value of the lower-case hex digit c, or -1 for another
 *	character.
 */
static int
hexdigit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

/*
 * hexbytes(name, text, out, outlen):
 *	The outlen bytes of the hex text at text, to out. A text of
 *	another length, or a character that is not lower-case hex,
 *	prints the failure and gives -1.
 */
static int
hexbytes(const char *name, const char *text, unsigned char *out, size_t outlen)
{
	size_t	 i, len;
	int	 hi, lo;

	len = strlen(text);
	if (len != 2 * outlen) {
		warnx("%s: the vector holds %zu characters, and the test "
		    "takes %zu bytes", name, len, outlen);
		return -1;
	}
	for (i = 0; i < outlen; i++) {
		hi = hexdigit(text[2 * i]);
		lo = hexdigit(text[2 * i + 1]);
		if (hi < 0 || lo < 0) {
			warnx("%s: the vector holds a character that is not "
			    "lower-case hex", name);
			return -1;
		}
		out[i] = (unsigned char)((hi << 4) | lo);
	}
	return 0;
}

/*
 * hexcheck(name, value, len, want):
 *	Compare the len bytes at value with the hex text at want. A
 *	difference prints the two values, and gives -1.
 */
static int
hexcheck(const char *name, const unsigned char *value, size_t len,
    const char *want)
{
	char	 got[2 * DERIVE_KEYLEN + 1];
	size_t	 i;

	if (len > DERIVE_KEYLEN) {
		warnx("%s: %zu bytes are too many for a vector", name, len);
		return -1;
	}
	for (i = 0; i < len; i++)
		snprintf(&got[2 * i], 3, "%02x", value[i]);
	got[2 * len] = '\0';
	if (strcmp(got, want) != 0) {
		warnx("%s: the value is %s, and the vector is %s", name, got,
		    want);
		return -1;
	}
	return 0;
}

/*
 * testroot(root, rootlen):
 *	root of the fixed test master, to the rootlen bytes at root.
 */
static int
testroot(unsigned char *root, size_t rootlen)
{
	if (derive_root(KAT_TEST_MASTER, strlen(KAT_TEST_MASTER), root,
	    rootlen) != 0) {
		warnx("root of the test master: the call fails");
		return -1;
	}
	return 0;
}

/*
 * testfactor(x, xlen):
 *	The device factor X of the test master, for the machine name
 *	of the vectors (KEY-DEVICE-1). test_client() and test_pin()
 *	take it.
 */
static int
testfactor(unsigned char *x, size_t xlen)
{
	unsigned char	 root[DERIVE_ROOTLEN];

	if (testroot(root, sizeof(root)) != 0)
		return -1;
	if (derive_device_factor(root, sizeof(root), KAT_TEST_MACHINE,
	    strlen(KAT_TEST_MACHINE), x, xlen) != 0) {
		warnx("the device factor: the call fails");
		return -1;
	}
	return 0;
}

/*
 * seckeycheck(name, key):
 *	Prove that the curve takes the DERIVE_KEYLEN bytes at key as
 *	a private key (KEY-CLIENT-2). The curve rejects 0, and it
 *	rejects the group order or more.
 */
static int
seckeycheck(const char *name, const unsigned char *key)
{
	if (secp256k1_ec_seckey_verify(secp256k1_context_static, key) != 1) {
		warnx("%s: the curve rejects it", name);
		return -1;
	}
	return 0;
}

/*
 * test_field():
 *	The products and the inverses of the vectors match, and the
 *	product of a byte and its inverse is 1 for each of the 255
 *	nonzero bytes (KEY-SHARE-2).
 */
static int
test_field(void)
{
	unsigned char	 got;
	unsigned int	 a;
	size_t		 i;
	int		 rv = 0;

	for (i = 0; i < KAT_SHARE_MUL_COUNT; i++) {
		got = share_mul(mul[i][0], mul[i][1]);
		if (got != mul[i][2]) {
			warnx("the product of %02x and %02x: the value is "
			    "%02x, and the vector is %02x", mul[i][0],
			    mul[i][1], got, mul[i][2]);
			rv = -1;
		}
	}
	for (i = 0; i < KAT_SHARE_INV_COUNT; i++) {
		got = share_inv(inv[i][0]);
		if (got != inv[i][1]) {
			warnx("the inverse of %02x: the value is %02x, and "
			    "the vector is %02x", inv[i][0], got, inv[i][1]);
			rv = -1;
		}
	}

	/*
	 * The vectors hold 7 inverses, and the field holds 255. This
	 * loop takes every nonzero byte, so a wrong inverse of any
	 * one of them fails the test.
	 */
	for (a = 1; a <= 0xff; a++) {
		got = share_mul((unsigned char)a, share_inv((unsigned char)a));
		if (got != 1) {
			warnx("the inverse of %02x: the product is %02x, and "
			    "the rule is 01", a, got);
			rv = -1;
			break;
		}
	}
	return rv;
}

/*
 * test_split():
 *	The share of each oracle matches the vector, at each
 *	threshold of the vectors (KEY-SHARE-5). The galois module
 *	of PyPI made the field arithmetic of the vectors, and the
 *	hmac module of Python made the coefficients, so they pin
 *	the coefficient label and the evaluation (TEST-SPLIT-4).
 */
static int
test_split(void)
{
	unsigned char		 secret[DERIVE_KEYLEN];
	unsigned char		 got[DERIVE_KEYLEN];
	char			 name[NAMELEN];
	const char *const	*share;
	size_t			 c;
	unsigned int		 k, i;
	int			 rv = 0;

	if (hexbytes("the split secret", KAT_SHARE_SECRET, secret,
	    sizeof(secret)) != 0)
		return -1;
	for (c = 0; c < nitems(thresholds); c++) {
		k = thresholds[c].threshold;
		share = thresholds[c].share;
		for (i = 1; i <= KAT_SHARE_ORACLES; i++) {
			snprintf(name, sizeof(name), "the share of the oracle "
			    "%u at the threshold %u", i, k);
			if (share_split(secret, sizeof(secret), k, i, got,
			    sizeof(got)) != 0) {
				warnx("%s: the call fails", name);
				rv = -1;
				continue;
			}
			if (hexcheck(name, got, sizeof(got),
			    share[i - 1]) != 0)
				rv = -1;
		}
	}
	return rv;
}

/*
 * test_combine():
 *	The index set of a threshold reconstructs the secret from
 *	the vector shares (KEY-SHARE-6). One share fewer than the
 *	threshold gives another value.
 *
 *	The shares come from the vectors, and not from
 *	share_split(), so a matched pair of defects in the two
 *	functions cannot hide here.
 */
static int
test_combine(void)
{
	unsigned char		 shares[SET_MAX * DERIVE_KEYLEN];
	unsigned char		 secret[DERIVE_KEYLEN];
	unsigned char		 got[DERIVE_KEYLEN];
	char			 name[NAMELEN];
	const char *const	*share;
	const unsigned int	*set;
	size_t			 c;
	unsigned int		 k, j;
	int			 fail, rv = 0;

	if (hexbytes("the split secret", KAT_SHARE_SECRET, secret,
	    sizeof(secret)) != 0)
		return -1;
	for (c = 0; c < nitems(thresholds); c++) {
		k = thresholds[c].threshold;
		share = thresholds[c].share;
		set = thresholds[c].set;
		if (k > SET_MAX) {
			warnx("the threshold %u: the index set is longer "
			    "than the buffer of the test", k);
			rv = -1;
			continue;
		}
		fail = 0;
		for (j = 0; j < k; j++) {
			snprintf(name, sizeof(name), "the share of the oracle "
			    "%u at the threshold %u", set[j], k);
			if (set[j] == 0 || set[j] > KAT_SHARE_ORACLES) {
				warnx("%s: the index set names no vector",
				    name);
				fail = 1;
				continue;
			}
			if (hexbytes(name, share[set[j] - 1],
			    &shares[j * DERIVE_KEYLEN], DERIVE_KEYLEN) != 0)
				fail = 1;
		}
		if (fail != 0) {
			rv = -1;
			continue;
		}
		snprintf(name, sizeof(name), "the secret of %u shares at the "
		    "threshold %u", k, k);
		if (share_combine(set, shares, k, got, sizeof(got)) != 0) {
			warnx("%s: the call fails", name);
			rv = -1;
		} else if (hexcheck(name, got, sizeof(got),
		    KAT_SHARE_SECRET) != 0)
			rv = -1;

		/*
		 * One share fewer must give another value. A
		 * threshold of 1 takes no share fewer, because
		 * share_combine() rejects a count of 0.
		 */
		if (k < 2)
			continue;
		if (share_combine(set, shares, k - 1, got, sizeof(got)) != 0) {
			warnx("the threshold %u: the call of %u shares fails",
			    k, k - 1);
			rv = -1;
		} else if (memcmp(got, secret, sizeof(got)) == 0) {
			warnx("the threshold %u: %u shares give the secret",
			    k, k - 1);
			rv = -1;
		}
	}
	return rv;
}

/*
 * test_single():
 *	With a threshold of 1, the share of every oracle index
 *	equals the secret (KEY-SHARE-7). The vectors hold 5 indexes,
 *	and this loop takes every index of a vault.
 */
static int
test_single(void)
{
	unsigned char	 secret[DERIVE_KEYLEN];
	unsigned char	 got[DERIVE_KEYLEN];
	unsigned int	 i;

	if (hexbytes("the split secret", KAT_SHARE_SECRET, secret,
	    sizeof(secret)) != 0)
		return -1;
	for (i = 1; i <= DERIVE_ORACLE_MAX; i++) {
		if (share_split(secret, sizeof(secret), 1, i, got,
		    sizeof(got)) != 0) {
			warnx("the threshold 1: the share of the oracle %u "
			    "fails", i);
			return -1;
		}
		if (memcmp(got, secret, sizeof(got)) != 0) {
			warnx("the threshold 1: the share of the oracle %u "
			    "differs from the secret", i);
			return -1;
		}
	}
	return 0;
}

/*
 * test_reject():
 *	The documented rejection gates of share_combine(),
 *	share_split() and pin_secret() give a failure (share.h,
 *	pin.h). Each case below names the mutation that it catches.
 *	Every one of these gates stands between a caller error and a
 *	wrong key, and no caller sees the difference without it.
 */
static int
test_reject(void)
{
	static const unsigned int	 repeated[2] = { 1, 1 };
	static const unsigned int	 zeroindex[2] = { 0, 2 };
	unsigned char			 secret[DERIVE_KEYLEN];
	unsigned char			 shares[2 * DERIVE_KEYLEN];
	unsigned char			 got[DERIVE_KEYLEN];
	unsigned char			 salt[DERIVE_KEYLEN];
	int				 rv = 0;

	if (hexbytes("the split secret", KAT_SHARE_SECRET, secret,
	    sizeof(secret)) != 0)
		return -1;
	if (hexbytes("the share of the oracle 1", share_k2[0], shares,
	    DERIVE_KEYLEN) != 0)
		return -1;
	if (hexbytes("the share of the oracle 2", share_k2[1],
	    &shares[DERIVE_KEYLEN], DERIVE_KEYLEN) != 0)
		return -1;

	/*
	 * A repeated index gives -1 (share.h). A removal of that gate
	 * gives a divisor of 0 for each weight. share_inv(0) gives 0,
	 * so both weights go to 0. share_combine() then gives 0, and
	 * the caller takes 32 zero bytes for the secret.
	 */
	if (share_combine(repeated, shares, 2, got, sizeof(got)) == 0) {
		warnx("a repeated index: share_combine() takes it");
		rv = -1;
	}

	/*
	 * An index of 0 gives -1 (share.h). An oracle index is 1-based,
	 * and 0 is the evaluation point of the secret (KEY-SHARE-5). A
	 * removal of that gate gives the first share the weight 1 and
	 * the second share the weight 0. share_combine() then gives 0,
	 * and the caller takes the first share for the secret.
	 */
	if (share_combine(zeroindex, shares, 2, got, sizeof(got)) == 0) {
		warnx("an index of 0: share_combine() takes it");
		rv = -1;
	}

	/*
	 * A count of 0 gives -1 (share.h). A removal of that gate runs
	 * no step of the interpolation. share_combine() then gives 0,
	 * and the caller takes 32 zero bytes for the secret.
	 */
	if (share_combine(set_k2, shares, 0, got, sizeof(got)) == 0) {
		warnx("a count of 0: share_combine() takes it");
		rv = -1;
	}

	/*
	 * A threshold outside 1 to DERIVE_ORACLE_MAX gives -1
	 * (share.h). The upper case carries the gate: a removal of it
	 * takes the threshold 256, because every coefficient label of
	 * that threshold fits its buffer. share_split() then gives 0
	 * and a share of a threshold that KEY-SHARE-1 forbids.
	 *
	 * The case of the threshold 0 catches a gate that gives 0 in
	 * place of -1. A removal of the whole gate still gives -1
	 * there, by another path: threshold - 1 wraps to UINT_MAX, and
	 * the label of that coefficient index needs 31 bytes of a
	 * buffer of 28.
	 */
	if (share_split(secret, sizeof(secret), 0, 1, got, sizeof(got)) == 0) {
		warnx("a threshold of 0: share_split() takes it");
		rv = -1;
	}
	if (share_split(secret, sizeof(secret), DERIVE_ORACLE_MAX + 1, 1, got,
	    sizeof(got)) == 0) {
		warnx("a threshold above the maximum: share_split() takes it");
		rv = -1;
	}

	/*
	 * An oracle index above DERIVE_ORACLE_MAX gives -1 (share.h). A
	 * removal of that gate casts 256 to the evaluation point 0, and
	 * p_b(0) is the secret itself (KEY-SHARE-4). share_split() then
	 * gives 0, and the caller takes the secret for a share.
	 */
	if (share_split(secret, sizeof(secret), 2, DERIVE_ORACLE_MAX + 1, got,
	    sizeof(got)) == 0) {
		warnx("an oracle index above the maximum: share_split() "
		    "takes it");
		rv = -1;
	}

	/*
	 * An output length other than PIN_SECRETLEN gives -1 (pin.h). A
	 * removal of that gate lets bcrypt_pbkdf(3) fill the shorter
	 * buffer, because its output length is free. pin_secret() then
	 * gives 0 and a pin secret that no oracle payload takes
	 * (KEY-PIN-3).
	 */
	memset(salt, 'a', sizeof(salt));
	if (pin_secret(KAT_PIN_PASSPHRASE, strlen(KAT_PIN_PASSPHRASE), salt,
	    sizeof(salt), KAT_PIN_ROUNDS, got, PIN_SECRETLEN - 1) == 0) {
		warnx("a short output: pin_secret() takes it");
		rv = -1;
	}
	return rv;
}

/*
 * test_client():
 *	The client key of the record and the canary client key match
 *	the vectors, and the curve takes each one (KEY-CLIENT-1,
 *	KEY-CLIENT-2).
 */
static int
test_client(void)
{
	unsigned char	 x[DERIVE_KEYLEN];
	unsigned char	 material[DERIVE_KEYLEN];
	unsigned char	 key[DERIVE_KEYLEN];
	int		 rv = 0;

	if (testfactor(x, sizeof(x)) != 0)
		return -1;
	if (derive_client_key(x, sizeof(x), KAT_TEST_ORACLE, KAT_TEST_SLOT,
	    key, sizeof(key)) != 0) {
		warnx("the client key: the call fails");
		rv = -1;
	} else {
		if (hexcheck("the client key", key, sizeof(key),
		    KAT_TEST_CLIENT_KEY) != 0)
			rv = -1;
		if (seckeycheck("the client key", key) != 0)
			rv = -1;
	}
	if (derive_client_key_canary(x, sizeof(x), KAT_TEST_ORACLE, key,
	    sizeof(key)) != 0) {
		warnx("the canary client key: the call fails");
		rv = -1;
	} else {
		if (hexcheck("the canary client key", key, sizeof(key),
		    KAT_TEST_CANARY_CLIENT_KEY) != 0)
			rv = -1;
		if (seckeycheck("the canary client key", key) != 0)
			rv = -1;
	}

	/*
	 * The edge material is 32 bytes of 0xff, and it stands above
	 * the group order. A reduction that skips the modulus gives
	 * that material back, and the curve rejects it.
	 */
	if (hexbytes("the edge material", KAT_TEST_EDGE_MATERIAL, material,
	    sizeof(material)) != 0)
		return -1;
	if (derive_client_reduce(material, sizeof(material), key,
	    sizeof(key)) != 0) {
		warnx("the edge client key: the call fails");
		return -1;
	}
	if (hexcheck("the edge client key", key, sizeof(key),
	    KAT_TEST_EDGE_CLIENT_KEY) != 0)
		rv = -1;
	if (seckeycheck("the edge client key", key) != 0)
		rv = -1;
	return rv;
}

/*
 * test_machine():
 *	The gate takes the machine name of the vectors, and a name
 *	of DERIVE_MACHINE_MAX bytes. It rejects an upper-case
 *	letter, a space, an empty name, and one byte more than the
 *	limit (KEY-DEVICE-3).
 */
static int
test_machine(void)
{
	static const struct {
		const char	*name;
		const char	*part;
	} bad[] = {
		{ "Laptop-1", "an upper-case letter" },
		{ "laptop 1", "a space" },
		{ "", "an empty name" },
	};
	char	 name[DERIVE_MACHINE_MAX + 1];
	size_t	 i;
	int	 rv = 0;

	if (derive_machine_check(KAT_TEST_MACHINE,
	    strlen(KAT_TEST_MACHINE)) != 0) {
		warnx("the machine name %s: the gate rejects it",
		    KAT_TEST_MACHINE);
		rv = -1;
	}
	for (i = 0; i < nitems(bad); i++) {
		if (derive_machine_check(bad[i].name,
		    strlen(bad[i].name)) == 0) {
			warnx("%s: the gate takes the machine name",
			    bad[i].part);
			rv = -1;
		}
	}

	/*
	 * The gate takes a length, and a name needs no terminator.
	 * The buffer holds one byte more than the limit, so the two
	 * calls stand on each side of the limit.
	 */
	memset(name, 'a', sizeof(name));
	if (derive_machine_check(name, DERIVE_MACHINE_MAX) != 0) {
		warnx("a machine name of %d bytes: the gate rejects it",
		    DERIVE_MACHINE_MAX);
		rv = -1;
	}
	if (derive_machine_check(name, sizeof(name)) == 0) {
		warnx("a machine name of %zu bytes: the gate takes it",
		    sizeof(name));
		rv = -1;
	}
	return rv;
}

/*
 * test_device():
 *	The device factor of the machine name and the pin salt of
 *	the record match the vectors (KEY-DEVICE-1, KEY-PIN-2).
 */
static int
test_device(void)
{
	unsigned char	 root[DERIVE_ROOTLEN];
	unsigned char	 x[DERIVE_KEYLEN];
	unsigned char	 salt[DERIVE_KEYLEN];
	int		 rv = 0;

	if (testroot(root, sizeof(root)) != 0)
		return -1;
	if (derive_device_factor(root, sizeof(root), KAT_TEST_MACHINE,
	    strlen(KAT_TEST_MACHINE), x, sizeof(x)) != 0) {
		warnx("the device factor: the call fails");
		return -1;
	}
	if (hexcheck("the device factor", x, sizeof(x),
	    KAT_TEST_DEVICE_FACTOR) != 0)
		rv = -1;
	if (derive_pin_salt(x, sizeof(x), KAT_TEST_ORACLE, KAT_TEST_SLOT,
	    salt, sizeof(salt)) != 0) {
		warnx("the pin salt: the call fails");
		rv = -1;
	} else if (hexcheck("the pin salt", salt, sizeof(salt),
	    KAT_TEST_PIN_SALT) != 0)
		rv = -1;
	return rv;
}

/*
 * test_pin():
 *	The pin secret of the test passphrase matches the vector, at
 *	the pin salt of the record and at the canary pin salt
 *	(KEY-PIN-3). The two salts give two values.
 *
 *	Each salt comes from root, and not from a hex vector, so a
 *	difference between the two vector files fails this test.
 */
static int
test_pin(void)
{
	unsigned char	 x[DERIVE_KEYLEN];
	unsigned char	 salt[DERIVE_KEYLEN];
	unsigned char	 entry[PIN_SECRETLEN];
	unsigned char	 canary[PIN_SECRETLEN];
	int		 rv = 0;

	if (testfactor(x, sizeof(x)) != 0)
		return -1;
	if (derive_pin_salt(x, sizeof(x), KAT_TEST_ORACLE, KAT_TEST_SLOT,
	    salt, sizeof(salt)) != 0) {
		warnx("the pin salt: the call fails");
		return -1;
	}
	if (pin_secret(KAT_PIN_PASSPHRASE, strlen(KAT_PIN_PASSPHRASE), salt,
	    sizeof(salt), KAT_PIN_ROUNDS, entry, sizeof(entry)) != 0) {
		warnx("the pin secret: the call fails");
		return -1;
	}
	if (hexcheck("the pin secret", entry, sizeof(entry),
	    KAT_PIN_ENTRY) != 0)
		rv = -1;
	if (derive_pin_salt_canary(x, sizeof(x), KAT_TEST_ORACLE, salt,
	    sizeof(salt)) != 0) {
		warnx("the canary pin salt: the call fails");
		return -1;
	}
	if (pin_secret(KAT_PIN_PASSPHRASE, strlen(KAT_PIN_PASSPHRASE), salt,
	    sizeof(salt), KAT_PIN_ROUNDS, canary, sizeof(canary)) != 0) {
		warnx("the canary pin secret: the call fails");
		return -1;
	}
	if (hexcheck("the canary pin secret", canary, sizeof(canary),
	    KAT_PIN_CANARY) != 0)
		rv = -1;
	if (memcmp(entry, canary, sizeof(entry)) == 0) {
		warnx("the pin secret: two salts give one value");
		rv = -1;
	}
	return rv;
}

/*
 * test_wraps():
 *	The wrap key of the record, the index key of the vault, the
 *	index wrap key, and the seal key of the canary check match
 *	the vectors (KEY-MASK-3, KEY-MASK-5, KEY-MASK-6,
 *	KEY-MASK-7).
 */
static int
test_wraps(void)
{
	unsigned char	 root[DERIVE_ROOTLEN];
	unsigned char	 mask[DERIVE_KEYLEN];
	unsigned char	 canary[DERIVE_KEYLEN];
	unsigned char	 key[DERIVE_KEYLEN];
	int		 rv = 0;

	if (testroot(root, sizeof(root)) != 0)
		return -1;
	if (hexbytes("the test mask", KAT_TEST_MASK, mask, sizeof(mask)) != 0)
		return -1;
	if (hexbytes("the canary mask", KAT_TEST_CANARY_MASK, canary,
	    sizeof(canary)) != 0)
		return -1;
	if (derive_wrap_key(mask, sizeof(mask), KAT_TEST_ORACLE,
	    KAT_TEST_SLOT, key, sizeof(key)) != 0) {
		warnx("the wrap key: the call fails");
		rv = -1;
	} else if (hexcheck("the wrap key", key, sizeof(key),
	    KAT_TEST_WRAP_KEY) != 0)
		rv = -1;
	if (derive_index_key(root, sizeof(root), key, sizeof(key)) != 0) {
		warnx("the index key: the call fails");
		rv = -1;
	} else if (hexcheck("the index key", key, sizeof(key),
	    KAT_TEST_INDEX_KEY) != 0)
		rv = -1;
	if (derive_index_wrap_key(canary, sizeof(canary), KAT_TEST_ORACLE,
	    key, sizeof(key)) != 0) {
		warnx("the index wrap key: the call fails");
		rv = -1;
	} else if (hexcheck("the index wrap key", key, sizeof(key),
	    KAT_TEST_INDEX_WRAP_KEY) != 0)
		rv = -1;
	if (derive_canary_check_key(canary, sizeof(canary), KAT_TEST_ORACLE,
	    key, sizeof(key)) != 0) {
		warnx("the canary check seal key: the call fails");
		rv = -1;
	} else if (hexcheck("the canary check seal key", key, sizeof(key),
	    KAT_TEST_CANARY_CHECK_KEY) != 0)
		rv = -1;
	return rv;
}

int
main(void)
{
	int	 rv = 0;

	rv |= test_field();
	rv |= test_split();
	rv |= test_combine();
	rv |= test_single();
	rv |= test_reject();
	rv |= test_client();
	rv |= test_machine();
	rv |= test_device();
	rv |= test_pin();
	rv |= test_wraps();
	return rv != 0;
}
