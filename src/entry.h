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
 * The entry model: the origin classes, the six entry types, the
 * field table of each type, and the TOTP code. The model is data,
 * and two tables hold it.
 *
 * entry_classes[] holds the four origin classes, with the secret
 * origin, the backup medium and the restore path of each one
 * (ENTRY-MODEL-1, ENTRY-MODEL-2). entry_types[] holds the six
 * types, with the field table, the secret field, the origin
 * classes and the candidate of each one (ENTRY-TYPES-1,
 * ENTRY-TYPES-4, ENTRY-TYPES-5). A program reads the two tables,
 * and it holds no list of its own.
 *
 * No row holds a policy attribute, and no function here takes one.
 * One reveal path opens every entry: the passphrase and a quorum
 * of masks (ENTRY-MODEL-3). Every type takes the one seal and the
 * one custody path, so this file holds no seal and no key
 * (ENTRY-TYPES-2).
 *
 * A field table takes the row type of vault.h, and it follows the
 * table contract of that file. The scanner reads an entry file
 * with the table of the type of it, and it adds no rule for an
 * entry (VAULT-FORMAT-6). Every entry file holds the metadata
 * fields type and slots, and the secret field of the type comes
 * first (VAULT-FORMAT-4, ENTRY-TYPES-5). A value holds no line
 * feed, so each field takes one line (VAULT-FORMAT-7).
 *
 * entry_version() gives the version of one slot: the position of
 * that slot in the slot list. The list holds every version
 * (ENTRY-ROTATION-2), and the plate re-derives the key of an old
 * slot, so an old version stays recoverable (ENTRY-ROTATION-3).
 *
 * entry_totp() computes one TOTP code offline, with HMAC from
 * libcrypto (ENTRY-TYPES-3). RFC 6238 states the construction.
 *
 * A TOTP key and a TOTP code are secrets. entry_totp() clears each
 * temporary on each exit path, and a failure leaves no code at the
 * output buffer (SEC-MEMORY-1). Each caller clears the buffers
 * that it owns.
 */

#ifndef ENTRY_H
#define ENTRY_H

#include <stddef.h>
#include <stdint.h>

#include "vault.h"

/* The origin classes (ENTRY-MODEL-1). */
enum entry_class {
	ENTRY_CLASS_DERIVED,	/* BIP85 from the master */
	ENTRY_CLASS_STORED,	/* an import from outside */
	ENTRY_CLASS_SOVEREIGN,	/* its own seed, made outside FuguPass */
	ENTRY_CLASS_SHADOW,	/* none; metadata only */
	ENTRY_CLASS_MAX
};

/*
 * The class of a new entry, without another statement
 * (ENTRY-MODEL-1). A type that does not take this class takes a
 * stated class, and entry_class_check() holds that rule.
 */
#define ENTRY_CLASS_DEFAULT	ENTRY_CLASS_DERIVED

/* The bit of one class, for the class set of a type row. */
#define ENTRY_CLASS_BIT(c)	(1 << (c))

/* The entry types (ENTRY-TYPES-1). */
enum entry_type {
	ENTRY_TYPE_PASSWORD,
	ENTRY_TYPE_MNEMONIC,
	ENTRY_TYPE_PASSPHRASE,
	ENTRY_TYPE_TOTP,
	ENTRY_TYPE_NOTE,
	ENTRY_TYPE_SHADOW,
	ENTRY_TYPE_MAX
};

/*
 * The candidate of the slot that a derived entry of one type
 * consumes (ENTRY-TYPES-4, KEY-BIP85). A stored, sovereign or
 * shadow entry consumes no candidate.
 */
enum entry_candidate {
	ENTRY_CANDIDATE_NONE,
	ENTRY_CANDIDATE_PWD,	/* the PWD BASE64 candidate */
	ENTRY_CANDIDATE_BIP39	/* the BIP39 child candidate */
};

/* The hash of a totp entry (ENTRY-TYPES-3). */
enum entry_totp_alg {
	ENTRY_TOTP_SHA1,
	ENTRY_TOTP_SHA256,
	ENTRY_TOTP_SHA512
};

/*
 * One origin class (ENTRY-MODEL-2). The three texts are the
 * columns of the table of the specification, and a program prints
 * them. in_place states the rotation of the class: a derived
 * secret comes back from a new slot (ENTRY-ROTATION-1), and every
 * other class holds the secret of the entry in the slot of that
 * entry (ENTRY-ROTATION-4).
 */
struct entry_class_row {
	const char	*name;
	const char	*origin;	/* the secret origin */
	const char	*backup;	/* the backup medium */
	const char	*restore;	/* the restore path */
	int		 in_place;	/* a rotation keeps the slot */
};

/*
 * One entry type (ENTRY-TYPES-1, ENTRY-TYPES-5). fields is the
 * field table of the type, for the scanner of vault.h. secret is
 * the name of the secret field, and it is NULL for a type that
 * holds no secret. classes is the set of the origin classes of the
 * type, one bit per class.
 */
struct entry_type_row {
	const char			*name;
	const struct vault_field	*fields;
	const char			*secret;
	int				 classes;
	enum entry_candidate		 candidate;
};

extern const struct entry_class_row	entry_classes[ENTRY_CLASS_MAX];
extern const struct entry_type_row	entry_types[ENTRY_TYPE_MAX];

/*
 * The digits of one code, and the bytes of one code with the
 * terminator. RFC 6238 gives 8 digits in the test vectors of it,
 * and 6 digits is the common count.
 */
#define ENTRY_TOTP_DIGITS_MIN	6
#define ENTRY_TOTP_DIGITS_MAX	8
#define ENTRY_TOTP_MAX		(ENTRY_TOTP_DIGITS_MAX + 1)

/*
 * The parameters of an entry file that states none of them. RFC
 * 6238 gives these three defaults.
 */
#define ENTRY_TOTP_ALG_DEFAULT		ENTRY_TOTP_SHA1
#define ENTRY_TOTP_DIGITS_DEFAULT	6
#define ENTRY_TOTP_PERIOD_DEFAULT	30

/*
 * entry_type_find(name, namelen, out):
 *	The entry type of the type name of namelen bytes at name, to
 *	out (ENTRY-TYPES-1). The name is the value of the type field
 *	of an entry file. A name that no row holds gives -1.
 */
int	entry_type_find(const char *, size_t, enum entry_type *);

/*
 * entry_class_check(type, class):
 *	0 when the type type takes the origin class class, and -1
 *	for every other pair (ENTRY-TYPES-5). The table of
 *	ENTRY-TYPES holds the classes of each type.
 */
int	entry_class_check(enum entry_type, enum entry_class);

/*
 * entry_totp_alg_find(name, namelen, out):
 *	The hash of the algorithm name of namelen bytes at name, to
 *	out. The name is the value of the totp-algorithm field:
 *	sha1, sha256 or sha512. Another name gives -1.
 */
int	entry_totp_alg_find(const char *, size_t, enum entry_totp_alg *);

/*
 * entry_version(slots, slotslen, slot, out):
 *	The version of the slot index slot, to out: the 1-based
 *	position of that slot in the slot list of slotslen bytes at
 *	slots (ENTRY-ROTATION-2). The list is the value of the slots
 *	field of the entry file, and the current version is the last
 *	position of it.
 *
 *	A list that the form rejects, a slot that the list does not
 *	hold, and a slot that the list holds twice each give -1
 *	(VAULT-FORMAT-7).
 */
int	entry_version(const char *, size_t, uint32_t, unsigned int *);

/*
 * entry_totp(key, keylen, alg, digits, period, at, out, outlen):
 *	The TOTP code of the key of keylen bytes at key, to the
 *	outlen bytes at out, with a terminator (ENTRY-TYPES-3).
 *	outlen must be ENTRY_TOTP_MAX.
 *
 *	alg is the hash of the HMAC, digits is ENTRY_TOTP_DIGITS_MIN
 *	to ENTRY_TOTP_DIGITS_MAX, period is the seconds of one step,
 *	and at is the Unix time of the code. period must be 1 or
 *	more, and keylen must be 1 or more. The step count is at
 *	divided by period, and the epoch of RFC 6238 is 0.
 *
 *	The code holds digits characters, with a leading zero for a
 *	short value. The call gives -1 for every value that the
 *	gates above reject, and for a failure of the HMAC.
 */
int	entry_totp(const unsigned char *, size_t, enum entry_totp_alg,
	    unsigned int, unsigned int, uint64_t, char *, size_t);

#endif /* ENTRY_H */
