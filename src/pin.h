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
 * The pin secret. One vault has one passphrase, and the reveal
 * secret is that passphrase (KEY-PIN-1). The pin secret of a record
 * is bcrypt_pbkdf(3) over the passphrase and the salt of the record
 * (KEY-PIN-3).
 *
 * pin_secret() is the one function of this tree that takes a typed
 * passphrase. A typed passphrase must not enter f, and the output
 * serves only as the pin secret of the oracle record (KEY-DERIVE-4,
 * KEY-PIN-4).
 *
 * The function takes buffers and lengths, and returns 0, or -1 on a
 * failure. A failed call leaves no secret in the output buffer
 * (SEC-MEMORY-1).
 *
 * The passphrase and the output are secrets. The passphrase enters
 * through readpassphrase(3), in the core process (SEC-MEMORY-4).
 * Each caller clears the buffers that it owns.
 */

#ifndef PIN_H
#define PIN_H

#include <stddef.h>

#include "derive.h"

#define PIN_SECRETLEN	32	/* the bytes of a pin secret (KEY-PIN-3) */

/*
 * pin_secret(pass, passlen, salt, saltlen, rounds, out, outlen):
 *	The pin secret of the passphrase of passlen bytes at pass,
 *	with the salt of saltlen bytes at salt, to the outlen bytes
 *	at out (KEY-PIN-3). saltlen must be DERIVE_KEYLEN, and outlen
 *	must be PIN_SECRETLEN. The salt of a record comes from
 *	derive_pin_salt() (KEY-PIN-2).
 *
 *	rounds is the round count of bcrypt_pbkdf(3), and the config
 *	file of the vault records it (KEY-PIN-5). The count sets the
 *	cost of one offline guess (SEC-FLOOR-2).
 */
int	pin_secret(const char *, size_t, const unsigned char *, size_t,
	    unsigned int, unsigned char *, size_t);

#endif /* PIN_H */
