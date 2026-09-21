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
 * The entry model: two tables, the version of a slot, and the TOTP
 * code. entry.h states the interface and the rules.
 *
 * The tables carry the model. entry_classes[] carries the origin
 * class table of ENTRY-MODEL, and entry_types[] carries the type
 * table of ENTRY-TYPES. A field table of one type takes the row
 * type of vault.h, so the scanner of that file reads every entry
 * file and holds no branch of its own (ENTRY-TYPES-5).
 *
 * Every entry file holds the metadata fields type and slots. The
 * secret field of a type comes first, and it carries
 * VAULT_FIELD_SECRET (VAULT-FORMAT-4). A shadow entry holds no
 * secret field, and the table of it holds metadata rows alone.
 *
 * No row repeats, because each field of an entry takes one line.
 *
 * HMAC comes from libcrypto, for the TOTP code alone
 * (ENTRY-TYPES-3). No other library enters this file.
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "entry.h"
#include "vault.h"

/* The highest slot index: a slot index stays below 2^31 (KEY-ENTRY-1). */
#define SLOT_MAX	INT32_MAX

/* The bytes of the step count of the HMAC message (RFC 6238). */
#define COUNTERLEN	8

/* The shortest HMAC that the truncation below takes (RFC 4226). */
#define MACLEN_MIN	20

/*
 * The field table of each entry type (ENTRY-TYPES-5). The secret
 * field comes first, then type and slots, then the metadata fields
 * of the type.
 *
 * The seed fingerprint and the TOTP key are lowercase hex, so the
 * scanner proves the form of them (VAULT-FORMAT-7). The site
 * policy transform, the user name and the URL are text, because no
 * unit states a narrower form.
 */
static const struct vault_field	 password_fields[] = {
	{ "password", VAULT_NAME_FIXED, VAULT_VALUE_TEXT,
	    VAULT_FIELD_SECRET },
	{ "type", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "slots", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ "username", VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 },
	{ "url", VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 },
	{ "transform", VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 },
	{ "version", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

static const struct vault_field	 mnemonic_fields[] = {
	{ "mnemonic", VAULT_NAME_FIXED, VAULT_VALUE_TEXT,
	    VAULT_FIELD_SECRET },
	{ "type", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "slots", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

static const struct vault_field	 passphrase_fields[] = {
	{ "passphrase", VAULT_NAME_FIXED, VAULT_VALUE_TEXT,
	    VAULT_FIELD_SECRET },
	{ "type", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "slots", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ "seed-fingerprint", VAULT_NAME_FIXED, VAULT_VALUE_HEX, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

static const struct vault_field	 totp_fields[] = {
	{ "totp-key", VAULT_NAME_FIXED, VAULT_VALUE_HEX,
	    VAULT_FIELD_SECRET },
	{ "type", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "slots", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ "totp-algorithm", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "totp-digits", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ "totp-period", VAULT_NAME_FIXED, VAULT_VALUE_NUMBER, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

static const struct vault_field	 note_fields[] = {
	{ "note", VAULT_NAME_FIXED, VAULT_VALUE_TEXT, VAULT_FIELD_SECRET },
	{ "type", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "slots", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

static const struct vault_field	 shadow_fields[] = {
	{ "type", VAULT_NAME_FIXED, VAULT_VALUE_WORD, 0 },
	{ "slots", VAULT_NAME_FIXED, VAULT_VALUE_SLOTS, 0 },
	{ "location", VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 },
	{ "custodian", VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 },
	{ "verified", VAULT_NAME_FIXED, VAULT_VALUE_DATE, 0 },
	{ NULL, VAULT_NAME_FIXED, VAULT_VALUE_TEXT, 0 }
};

/*
 * The origin classes (ENTRY-MODEL-1, ENTRY-MODEL-2). The three
 * texts of a row are the columns of the table of the
 * specification.
 *
 * A rotation of a derived entry takes a new slot, because the
 * master derives the secret of it from the slot (ENTRY-ROTATION-1,
 * KEY-BIP85). Each other class holds the secret of the entry in
 * the slot of that entry: a stored entry takes the new secret in
 * place (ENTRY-ROTATION-4), a sovereign secret comes from a seed
 * outside FuguPass, and a shadow entry holds no secret.
 */
const struct entry_class_row entry_classes[ENTRY_CLASS_MAX] = {
	[ENTRY_CLASS_DERIVED]	= { "derived", "BIP85 from the master",
	    "the master plate", "re-derivation from the plate", 0 },
	[ENTRY_CLASS_STORED]	= { "stored", "an import from outside",
	    "any copy of the shared set", "the plate plus a copy", 1 },
	[ENTRY_CLASS_SOVEREIGN]	= { "sovereign",
	    "its own seed, made outside FuguPass", "its own plate",
	    "its own plate", 1 },
	[ENTRY_CLASS_SHADOW]	= { "shadow", "none; metadata only",
	    "any copy of the shared set", "the plate plus a copy", 1 }
};

/*
 * The entry types (ENTRY-TYPES-1). A row holds the field table,
 * the secret field, the origin classes and the candidate of one
 * type (ENTRY-TYPES-4, ENTRY-TYPES-5). A totp entry is
 * stored-origin (ENTRY-TYPES-3), and a shadow entry is
 * shadow-origin.
 */
const struct entry_type_row entry_types[ENTRY_TYPE_MAX] = {
	[ENTRY_TYPE_PASSWORD]	= { "password", password_fields, "password",
	    ENTRY_CLASS_BIT(ENTRY_CLASS_DERIVED) |
	    ENTRY_CLASS_BIT(ENTRY_CLASS_STORED), ENTRY_CANDIDATE_PWD },
	[ENTRY_TYPE_MNEMONIC]	= { "mnemonic", mnemonic_fields, "mnemonic",
	    ENTRY_CLASS_BIT(ENTRY_CLASS_DERIVED) |
	    ENTRY_CLASS_BIT(ENTRY_CLASS_STORED) |
	    ENTRY_CLASS_BIT(ENTRY_CLASS_SOVEREIGN), ENTRY_CANDIDATE_BIP39 },
	[ENTRY_TYPE_PASSPHRASE]	= { "passphrase", passphrase_fields,
	    "passphrase", ENTRY_CLASS_BIT(ENTRY_CLASS_DERIVED) |
	    ENTRY_CLASS_BIT(ENTRY_CLASS_STORED) |
	    ENTRY_CLASS_BIT(ENTRY_CLASS_SOVEREIGN), ENTRY_CANDIDATE_PWD },
	[ENTRY_TYPE_TOTP]	= { "totp", totp_fields, "totp-key",
	    ENTRY_CLASS_BIT(ENTRY_CLASS_STORED), ENTRY_CANDIDATE_NONE },
	[ENTRY_TYPE_NOTE]	= { "note", note_fields, "note",
	    ENTRY_CLASS_BIT(ENTRY_CLASS_STORED), ENTRY_CANDIDATE_NONE },
	[ENTRY_TYPE_SHADOW]	= { "shadow", shadow_fields, NULL,
	    ENTRY_CLASS_BIT(ENTRY_CLASS_SHADOW), ENTRY_CANDIDATE_NONE }
};

/*
 * slot_number(text, len, out):
 *	The value of the unpadded decimal ASCII of len bytes at
 *	text, to out (VAULT-FORMAT-7). A leading zero, a character
 *	that is not a digit, and a value above SLOT_MAX each give
 *	-1. The scanner of vault.c holds this same rule for a file,
 *	and this function reads the value that the scanner took.
 */
static int
slot_number(const char *text, size_t len, uint32_t *out)
{
	uint64_t	 value = 0;
	size_t		 i;

	/* 10 digits hold every value below 2^32. */
	if (len == 0 || len > 10 || (len > 1 && text[0] == '0'))
		return -1;
	for (i = 0; i < len; i++) {
		if (text[i] < '0' || text[i] > '9')
			return -1;
		value = value * 10 + (uint64_t)(text[i] - '0');
	}
	if (value > (uint64_t)SLOT_MAX)
		return -1;
	*out = (uint32_t)value;
	return 0;
}

/*
 * name_eq(name, namelen, text):
 *	1 when the namelen bytes at name are the string at text, and
 *	0 for every other pair. A name of a table holds no NUL byte,
 *	and a scanned value holds none either.
 */
static int
name_eq(const char *name, size_t namelen, const char *text)
{
	return namelen == strlen(text) && memcmp(name, text, namelen) == 0;
}

int
entry_type_find(const char *name, size_t namelen, enum entry_type *out)
{
	size_t	 i;

	if (name == NULL || out == NULL || namelen == 0)
		return -1;
	for (i = 0; i < (size_t)ENTRY_TYPE_MAX; i++) {
		if (!name_eq(name, namelen, entry_types[i].name))
			continue;
		*out = (enum entry_type)i;
		return 0;
	}
	return -1;
}

int
entry_class_check(enum entry_type type, enum entry_class class)
{
	if ((unsigned int)type >= ENTRY_TYPE_MAX ||
	    (unsigned int)class >= ENTRY_CLASS_MAX)
		return -1;
	if ((entry_types[type].classes & ENTRY_CLASS_BIT(class)) == 0)
		return -1;
	return 0;
}

int
entry_totp_alg_find(const char *name, size_t namelen, enum entry_totp_alg *out)
{
	static const struct {
		const char		*name;
		enum entry_totp_alg	 alg;
	} algs[] = {
		{ "sha1", ENTRY_TOTP_SHA1 },
		{ "sha256", ENTRY_TOTP_SHA256 },
		{ "sha512", ENTRY_TOTP_SHA512 }
	};
	size_t	 i;

	if (name == NULL || out == NULL || namelen == 0)
		return -1;
	for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
		if (!name_eq(name, namelen, algs[i].name))
			continue;
		*out = algs[i].alg;
		return 0;
	}
	return -1;
}

int
entry_version(const char *slots, size_t slotslen, uint32_t slot,
    unsigned int *out)
{
	const char	*comma;
	uint32_t	 value;
	size_t		 at = 0, part;
	unsigned int	 found = 0, position = 0;

	if (slots == NULL || out == NULL || slotslen == 0)
		return -1;

	/*
	 * The walk reads the whole list, so a list that the form
	 * rejects gives -1, and a slot of two positions gives -1
	 * too. A version names one position.
	 */
	for (;;) {
		comma = memchr(&slots[at], ',', slotslen - at);
		part = (comma == NULL) ? slotslen - at :
		    (size_t)(comma - slots) - at;
		if (slot_number(&slots[at], part, &value) != 0)
			return -1;
		position++;
		if (value == slot) {
			if (found != 0)
				return -1;
			found = position;
		}
		if (comma == NULL)
			break;
		at += part + 1;
	}
	if (found == 0)
		return -1;
	*out = found;
	return 0;
}

int
entry_totp(const unsigned char *key, size_t keylen, enum entry_totp_alg alg,
    unsigned int digits, unsigned int period, uint64_t at, char *out,
    size_t outlen)
{
	unsigned char	 mac[EVP_MAX_MD_SIZE], counter[COUNTERLEN];
	const EVP_MD	*md;
	uint64_t	 steps;
	uint32_t	 binary, modulo;
	unsigned int	 i, maclen = 0;
	size_t		 offset;
	int		 n, rv = -1;

	if (key == NULL || out == NULL || keylen == 0 ||
	    keylen > (size_t)INT_MAX || period == 0 ||
	    digits < ENTRY_TOTP_DIGITS_MIN || digits > ENTRY_TOTP_DIGITS_MAX ||
	    outlen != ENTRY_TOTP_MAX)
		return -1;
	switch (alg) {
	case ENTRY_TOTP_SHA1:
		md = EVP_sha1();
		break;
	case ENTRY_TOTP_SHA256:
		md = EVP_sha256();
		break;
	case ENTRY_TOTP_SHA512:
		md = EVP_sha512();
		break;
	default:
		return -1;
	}

	/*
	 * The message is the step count, as 8 big-endian bytes. The
	 * epoch of the count is 0, and one step is period seconds
	 * (RFC 6238).
	 */
	steps = at / period;
	for (i = 0; i < COUNTERLEN; i++)
		counter[COUNTERLEN - 1 - i] =
		    (unsigned char)((steps >> (8 * i)) & 0xff);

	if (HMAC(md, key, (int)keylen, counter, sizeof(counter), mac,
	    &maclen) == NULL || maclen < MACLEN_MIN ||
	    maclen > sizeof(mac))
		goto out;

	/*
	 * The dynamic truncation of RFC 4226: the low 4 bits of the
	 * last byte give the offset, and the 4 bytes there give a
	 * 31-bit value. The offset is 15 or less, so the 4 bytes sit
	 * inside an HMAC of MACLEN_MIN bytes.
	 */
	offset = mac[maclen - 1] & 0x0f;
	binary = ((uint32_t)(mac[offset] & 0x7f) << 24) |
	    ((uint32_t)mac[offset + 1] << 16) |
	    ((uint32_t)mac[offset + 2] << 8) | (uint32_t)mac[offset + 3];

	for (modulo = 1, i = 0; i < digits; i++)
		modulo *= 10;
	n = snprintf(out, outlen, "%0*u", (int)digits, binary % modulo);
	if (n < 0 || (size_t)n != digits)
		goto out;
	rv = 0;
out:
	explicit_bzero(mac, sizeof(mac));
	explicit_bzero(counter, sizeof(counter));
	if (rv != 0)
		explicit_bzero(out, outlen);
	return rv;
}
