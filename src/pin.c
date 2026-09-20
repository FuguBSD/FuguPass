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
 * The pin secret: one call of bcrypt_pbkdf(3) over the passphrase
 * and the salt of one record. pin.h states the interface.
 *
 * This file holds the one function of the tree that takes a typed
 * passphrase (KEY-DERIVE-4). Every other secret of the tree derives
 * from the master, and a passphrase is not a high-entropy key
 * (KEY-DERIVE-3).
 *
 * bcrypt_pbkdf(3) comes from libutil, and each directory that links
 * the archive adds -lutil to the link line. No other library enters
 * this file (D-15).
 */

#include <stddef.h>
#include <string.h>
#include <util.h>

#include "derive.h"
#include "pin.h"

int
pin_secret(const char *pass, size_t passlen, const unsigned char *salt,
    size_t saltlen, unsigned int rounds, unsigned char *out, size_t outlen)
{
	if (saltlen != DERIVE_KEYLEN || outlen != PIN_SECRETLEN)
		return -1;

	/*
	 * bcrypt_pbkdf(3) rejects an empty passphrase, an empty salt
	 * and a round count of 0, and it gives -1 for each of them.
	 * The output length is free, and PIN_SECRETLEN bytes match
	 * the payload of the oracle (KEY-PIN-3).
	 */
	if (bcrypt_pbkdf(pass, passlen, salt, saltlen, out, outlen,
	    rounds) != 0) {
		explicit_bzero(out, outlen);
		return -1;
	}
	return 0;
}
