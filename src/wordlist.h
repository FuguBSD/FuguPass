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
 * The word list API. wordlist.c holds the 2048 words of the BIP39
 * English list, and this file gives the two directions of the map:
 * the word of an index, and the index of a word. The index of a word
 * is its 0-based position in the list.
 *
 * Both functions return 0, or -1 on a failure. A failed call writes
 * nothing to an output. The list is public data. The word that a
 * caller gives to wordlist_index() can be a secret, so that function
 * reads the whole list at each call (SEC-MEMORY-2).
 */

#ifndef WORDLIST_H
#define WORDLIST_H

#include <stddef.h>

#define WORDLIST_COUNT	2048	/* the words of the list */
#define WORDLIST_MAX	8	/* the longest word, without the terminator */

/*
 * The SHA-256 of the word source, as 64 lower-case hex characters.
 * The digest covers the 2048 words, with one line feed after each
 * word and no other byte. FuguSeed pins this same digest for this
 * same list, and it names the list FuguSeed LIST-SOURCE-1. A test
 * computes the digest of the table and compares it with this
 * constant, so the two projects agree on the list by one number.
 */
#define WORDLIST_DIGEST \
	"2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

/*
 * wordlist_word(index, buf, buflen):
 *	Copy the word of index to buf, with a terminator. buf holds
 *	buflen bytes, and WORDLIST_MAX + 1 bytes are sufficient for
 *	every word. A failure is an index of WORDLIST_COUNT or more,
 *	and a buffer that is too small for the word.
 */
int	wordlist_word(size_t, char *, size_t);

/*
 * wordlist_index(word, wordlen, index):
 *	The index of the word of wordlen bytes at word. The bytes
 *	carry no terminator. A failure is a word that the list does
 *	not hold.
 */
int	wordlist_index(const char *, size_t, size_t *);

#endif /* WORDLIST_H */
