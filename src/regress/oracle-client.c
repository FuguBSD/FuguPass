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
 * The driver of the record tests. The interop harness starts a
 * counterparty, and it runs this program against that oracle
 * (TEST-HARNESS-1, TEST-HARNESS-6). A test of a record needs a live
 * oracle, so every leg lives in the harness, and this program holds
 * no test of its own.
 *
 * The tool of the vault does not exist yet, and this program stands
 * in for it. src/oracle.c holds every rule of a record, and this
 * file adds the arguments, the report, and the caller of the
 * decrypt.
 *
 * The four commands are:
 *
 *	oracle-client enroll <vault> <oracle> <slot>
 *	oracle-client reveal <vault> <oracle> <slot>
 *	oracle-client canary <vault> <oracle>
 *	oracle-client lock <vault> <oracle> <slot>
 *
 * <vault> is the vault directory, <oracle> is the 1-based position
 * of the oracle list, and <slot> is the slot index of the entry. A
 * canary record takes no slot index (ORC-RECORDS-2). lock sends the
 * one wrong attempt of a revocation at the revocation counter, and
 * it reads no passphrase (ORC-REVOKE-8, TEST-HARNESS-3). The leg
 * then proves junk on every get_pin and an HTTP error on every
 * set_pin of that record.
 *
 * The URL and the static public key of the position come from
 * <vault>/machine/config, because the record client reads the two
 * provisioned values from that file (ORC-PROVISION-1,
 * ORC-PROVISION-2). The file also names the machine, the threshold
 * k, and the round count of the pin secret. The command line
 * therefore holds the three values that the config file does not.
 * The harness writes the config file, and it states the wrong URL
 * and the wrong static key of a leg there.
 *
 * The master is the fixed test master of tests/vectors/derive.h, a
 * public constant of the tests (TEST-KAT-4). The program derives
 * the device factor X of the machine name of the config, and the
 * entry key K_e of the slot, from that master (KEY-DEVICE-1,
 * KEY-DEVICE-4, KEY-ENTRY-2). No ceremony writes machine/factor
 * yet, and the harness cannot derive X, so this program derives it
 * again at each run. A master on the command line would stand in a
 * process list, and a master on the standard input would take the
 * line of the passphrase.
 *
 * The program reads the passphrase on the standard input, of one
 * line with a line feed, because it drives no terminal. A canary
 * enrollment reads the passphrase twice, so it takes two lines
 * (ORC-CANARY-6).
 *
 * The program prints one line on the standard output, and it exits
 * 0. The first word of the line is the state of the call:
 *
 *	ok		The call gave 0.
 *	junk		A reveal gave the share of another mask, or a
 *			canary round trip gave another mask.
 *	auth		A 200 answer failed the authentication of the
 *			oracle.
 *	status		The oracle answered another status than 200.
 *	transport	The transport failed.
 *	error		The record client reported a local failure: an
 *			argument, a derivation, or a file. A mistyped
 *			second read of a canary takes this word as
 *			well, because one value of the record client
 *			reports every local failure.
 *
 * A reveal adds two fields to the line: the share, and the answer
 * plaintext s_ei, each of 64 lower-case hex characters. A junk
 * answer takes the same two fields of the same count of characters,
 * so a leg sees one response shape for a wrong passphrase, for a
 * wiped record, and for a counter violation (ORC-REVEAL-4). A leg
 * reads the second field for the stable answer of an unchanged
 * record, and oracle_reveal() gives that value to this one caller
 * (ORC-REVEAL-2, TEST-MASK-1).
 *
 * The decrypt of the caller is the one junk detector of a reveal
 * (ORC-REVEAL-4, VAULT-SEAL-4), and this program opens no entry. It
 * stands in for that decrypt: it derives share(K_e, i) from the
 * master again, and it compares the two shares. A reveal of the
 * enrolled mask gives that same share, and a reveal of another mask
 * gives another share (KEY-MASK-3). The share itself takes no mask,
 * so a re-enrollment keeps it and changes the mask alone
 * (KEY-SHARE-5).
 *
 * A failure of the program itself exits 1 with a message on the
 * standard error, and it prints no state line. The state line
 * therefore names the answer of the record client alone.
 *
 * The master, the passphrase, the device factor, the entry key, the
 * share and the mask are secrets of the shape of a live run. Each
 * one lives in a buffer of main(), and every exit path of main()
 * clears each of them (SEC-MEMORY-1).
 */

#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "derive.h"
#include "envelope.h"
#include "oracle.h"
#include "share.h"
#include "vault.h"

/*
 * The vectors, one directory below tests. Two files carry the name
 * derive.h: the interface of the derivation core, and the vectors
 * of it. The include above takes the interface, and the include
 * below carries the directory name, which the source directory does
 * not hold. No order of the search path can exchange the two files.
 */
#include "vectors/derive.h"

/*
 * Each of the two files sets a guard of its own, and both files
 * must enter this one. A build that reaches one file only stops
 * here.
 */
#if !defined(DERIVE_H) || !defined(VECTORS_DERIVE_H)
#error an include of oracle-client.c reached the wrong derive.h
#endif

/*
 * The bytes of the config file that this program takes. A vault
 * holds up to 255 positions, and one position line takes 400 bytes
 * or fewer (VAULT-CONFIG-1).
 */
#define CONFIG_MAX	131072

/*
 * One passphrase line of the standard input, with the line feed and
 * the terminator. A passphrase takes any length (KEY-PIN-1), and
 * this bound is the bound of this program.
 */
#define PASSLINE_MAX	1024

static void	 usage(void);
static int	 config_load(const char *, struct vault_config *);
static int	 pass_line(char *, size_t, size_t *);
static void	 print_hex(const unsigned char *, size_t);
static void	 report(int, const unsigned char *, const unsigned char *);
static int	 reveal(const struct oracle_ctx *, uint32_t,
		    const unsigned char *, size_t, unsigned char *,
		    unsigned char *);

/*
 * usage():
 *	The four commands, to the standard error, and exit 1. A
 *	wrong argument prints no state line.
 */
static void
usage(void)
{
	fprintf(stderr,
	    "usage: oracle-client enroll <vault> <oracle> <slot>\n"
	    "       oracle-client reveal <vault> <oracle> <slot>\n"
	    "       oracle-client canary <vault> <oracle>\n"
	    "       oracle-client lock <vault> <oracle> <slot>\n");
	exit(1);
}

/*
 * config_load(vault, cfg):
 *	The config file of the vault directory vault, to cfg
 *	(VAULT-CONFIG-1). The config carries no seal, so the file
 *	holds the text that vault_config_read() takes
 *	(VAULT-CONFIG-2).
 *
 *	A file that does not open, a file of CONFIG_MAX bytes or
 *	more, and a file that the reader rejects each give -1.
 */
static int
config_load(const char *vault, struct vault_config *cfg)
{
	char	 path[PATH_MAX];
	char	*text;
	FILE	*fp;
	size_t	 len;
	int	 rv = -1;

	if (vault_path(path, sizeof(path), vault, VAULT_FILE_CONFIG,
	    NULL) != 0)
		return -1;
	if ((text = malloc(CONFIG_MAX)) == NULL)
		return -1;
	if ((fp = fopen(path, "r")) == NULL) {
		free(text);
		return -1;
	}
	len = fread(text, 1, CONFIG_MAX, fp);
	if (ferror(fp) == 0 && feof(fp) != 0 && len != 0)
		rv = vault_config_read(text, len, cfg);
	fclose(fp);
	free(text);
	return rv;
}

/*
 * pass_line(buf, size, len):
 *	One line of the standard input, to the size bytes at buf,
 *	and the bytes of it to len. The line feed ends the line, and
 *	buf takes the line without it.
 *
 *	A read failure, an end of the input, and a line of size
 *	bytes or more each give -1. A failure clears buf, because
 *	the buffer can then hold a part of a passphrase
 *	(SEC-MEMORY-1).
 */
static int
pass_line(char *buf, size_t size, size_t *len)
{
	size_t	 n;

	*len = 0;
	if (fgets(buf, (int)size, stdin) == NULL) {
		explicit_bzero(buf, size);
		return -1;
	}
	n = strlen(buf);
	if (n == 0 || buf[n - 1] != '\n') {
		explicit_bzero(buf, size);
		return -1;
	}
	buf[--n] = '\0';
	*len = n;
	return 0;
}

/*
 * print_hex(bytes, len):
 *	The len bytes at bytes, to the standard output, as
 *	lower-case hex of two characters for each byte.
 */
static void
print_hex(const unsigned char *bytes, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		printf("%02x", bytes[i]);
}

/*
 * report(state, share, mask):
 *	The one line of one answer, to the standard output. The
 *	state takes one word, and a reveal adds the share and the
 *	answer plaintext of it. A command that gives no share gives
 *	two NULL pointers, and a state that carries no answer takes
 *	the word alone.
 */
static void
report(int state, const unsigned char *share, const unsigned char *mask)
{
	const char	*word;

	switch (state) {
	case 0:
		word = "ok";
		break;
	case ORACLE_EJUNK:
		word = "junk";
		break;
	case ORACLE_EAUTH:
		word = "auth";
		break;
	case ORACLE_ESTATUS:
		word = "status";
		break;
	case ORACLE_ETRANSPORT:
		word = "transport";
		break;
	default:
		word = "error";
		break;
	}
	printf("%s", word);
	if ((state == 0 || state == ORACLE_EJUNK) && share != NULL &&
	    mask != NULL) {
		printf(" ");
		print_hex(share, DERIVE_KEYLEN);
		printf(" ");
		print_hex(mask, ENVELOPE_MASKLEN);
	}
	printf("\n");
}

/*
 * reveal(ctx, slot, key, keylen, share, mask):
 *	One reveal of the record of the slot index slot, with the
 *	share of that oracle to the DERIVE_KEYLEN bytes at share,
 *	and the answer plaintext to the ENVELOPE_MASKLEN bytes at
 *	mask. key is the entry key K_e of the slot, of keylen bytes.
 *
 *	The call gives the state of oracle_reveal(), and it gives
 *	ORACLE_EJUNK for a share other than share(K_e, i). That
 *	comparison stands in for the decrypt of the caller
 *	(ORC-REVEAL-4, ORC-QUORUM-4). A state other than 0 leaves
 *	mask as it was, so the caller of a failure prints no field.
 */
static int
reveal(const struct oracle_ctx *ctx, uint32_t slot, const unsigned char *key,
    size_t keylen, unsigned char *share, unsigned char *mask)
{
	unsigned char	 want[DERIVE_KEYLEN];
	int		 rv;

	if ((rv = oracle_reveal(ctx, slot, share, DERIVE_KEYLEN, mask)) != 0)
		return rv;

	/*
	 * The share of a record comes from the threshold of the
	 * vault and the oracle index, as the enrollment took it
	 * (KEY-SHARE-5).
	 */
	rv = -1;
	if (share_split(key, keylen, ctx->config->threshold, ctx->oracle, want,
	    sizeof(want)) == 0)
		rv = (timingsafe_bcmp(share, want, sizeof(want)) == 0) ? 0 :
		    ORACLE_EJUNK;
	explicit_bzero(want, sizeof(want));
	return rv;
}

int
main(int argc, char *argv[])
{
	struct oracle_ctx	 ctx;
	struct vault_config	*cfg;
	unsigned char		 root[DERIVE_ROOTLEN];
	unsigned char		 factor[DERIVE_KEYLEN];
	unsigned char		 key[DERIVE_KEYLEN];
	unsigned char		 share[DERIVE_KEYLEN];
	unsigned char		 mask[ENVELOPE_MASKLEN];
	char			 pass[PASSLINE_MAX], again[PASSLINE_MAX];
	const char		*errstr, *fail = NULL;
	long long		 number;
	size_t			 passlen = 0, againlen = 0;
	uint32_t		 slot = 0;
	unsigned int		 oracle;
	int			 canary, lock, state;

	memset(key, 0, sizeof(key));
	memset(share, 0, sizeof(share));
	memset(mask, 0, sizeof(mask));
	memset(pass, 0, sizeof(pass));
	memset(again, 0, sizeof(again));

	if (argc < 4)
		usage();
	canary = (strcmp(argv[1], "canary") == 0);
	lock = (strcmp(argv[1], "lock") == 0);
	if (canary ? argc != 4 : argc != 5)
		usage();
	if (!canary && !lock && strcmp(argv[1], "enroll") != 0 &&
	    strcmp(argv[1], "reveal") != 0)
		usage();

	number = strtonum(argv[3], 1, DERIVE_ORACLE_MAX, &errstr);
	if (errstr != NULL)
		errx(1, "the oracle index is %s: %s", errstr, argv[3]);
	oracle = (unsigned int)number;
	if (!canary) {
		number = strtonum(argv[4], 0, VAULT_SLOT_MAX, &errstr);
		if (errstr != NULL)
			errx(1, "the slot index is %s: %s", errstr, argv[4]);
		slot = (uint32_t)number;
	}

	/*
	 * The struct of the config takes about 100 kilobytes, so it
	 * takes no place on the stack. It holds the URL and the
	 * static public key of each position, and both are public
	 * (ORC-PROVISION-1).
	 */
	if ((cfg = malloc(sizeof(*cfg))) == NULL)
		err(1, "malloc");
	if (config_load(argv[2], cfg) != 0) {
		fail = "the config of the vault does not read";
		goto out;
	}

	if (derive_root(KAT_TEST_MASTER, strlen(KAT_TEST_MASTER), root,
	    sizeof(root)) != 0 ||
	    derive_device_factor(root, sizeof(root), cfg->machine,
	    strlen(cfg->machine), factor, sizeof(factor)) != 0) {
		fail = "the device factor does not derive";
		goto out;
	}
	if (!canary && derive_entry_key(root, sizeof(root), slot, key,
	    sizeof(key)) != 0) {
		fail = "the entry key does not derive";
		goto out;
	}

	/* root reaches its last use here (SEC-MEMORY-6). */
	explicit_bzero(root, sizeof(root));

	/*
	 * A lock takes no passphrase: the revocation sends a random
	 * pin secret, and the owner of the plate types none
	 * (ORC-REVOKE-4).
	 */
	if (!lock && pass_line(pass, sizeof(pass), &passlen) != 0) {
		fail = "the standard input holds no passphrase line";
		goto out;
	}
	if (canary && pass_line(again, sizeof(again), &againlen) != 0) {
		fail = "the standard input holds no second passphrase line";
		goto out;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.vault = argv[2];
	ctx.config = cfg;
	ctx.factor = factor;
	ctx.factorlen = sizeof(factor);
	ctx.pass = lock ? NULL : pass;
	ctx.passlen = passlen;
	ctx.oracle = oracle;

	if (canary) {
		state = oracle_canary_enroll(&ctx, again, againlen);
		report(state, NULL, NULL);
	} else if (lock) {
		state = oracle_revoke(&ctx, slot, 0, 0);
		report(state, NULL, NULL);
	} else if (strcmp(argv[1], "enroll") == 0) {
		state = oracle_enroll(&ctx, slot, key, sizeof(key));
		report(state, NULL, NULL);
	} else {
		state = reveal(&ctx, slot, key, sizeof(key), share, mask);
		report(state, share, mask);
	}
out:
	explicit_bzero(root, sizeof(root));
	explicit_bzero(factor, sizeof(factor));
	explicit_bzero(key, sizeof(key));
	explicit_bzero(share, sizeof(share));
	explicit_bzero(mask, sizeof(mask));
	explicit_bzero(pass, sizeof(pass));
	explicit_bzero(again, sizeof(again));
	free(cfg);
	if (fail != NULL)
		errx(1, "%s", fail);
	return 0;
}
