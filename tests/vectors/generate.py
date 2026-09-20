#!/usr/bin/env python3
#
# Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""The generator of the known-answer vectors (TEST-KAT-5).

The script writes the header of the vectors to the standard output.
A developer runs it once, and commits the header:

    python3 tests/vectors/generate.py > tests/vectors/derive.h

The regress build then needs no Python. The script is a second
implementation of the derivation tree. It reads no file of the C
build, it copies no C code, and it takes the Python standard library
only. Each constant below names the standard that fixes it. A
difference between the two implementations is a defect of one of
them, and the known-answer test shows that difference.

Every step of every BIP85 path is hardened, so the script needs no
point of the curve. One addition modulo the order of the group gives
the private key of a child.

The custody vectors need one oracle answer, and this script sends
no request. Two public test masks stand in place of an answer, and
the header names them as public constants.

The script proves its own data before it prints. It proves the word
list against the pinned digest, and it proves the BIP85 master
against the extended key of the BIP85 document. It proves that the
client key falls inside the range of the curve. A failed proof stops
the run, and the script prints nothing.
"""

import base64
import hashlib
import hmac

# The order of the secp256k1 group, from SEC 2 version 2, section
# 2.4.1. A BIP32 step reduces the sum of two keys modulo this number.
GROUP_ORDER = int(
    "fffffffffffffffffffffffffffffffe"
    "baaedce6af48a03bbfd25e8cd0364141", 16)

# The fixed HMAC key of the BIP32 master, as the 12 bytes of its
# ASCII string. BIP32 fixes that string, and D-21 bans the first word
# of it, so the bytes stand here in place of the text.
BIP32_MASTER_KEY = bytes.fromhex("426974636f696e2073656564")

# The hardened bit of a child index (BIP32).
HARDENED = 0x80000000

# The BIP39 seed: PBKDF2-HMAC-SHA512 over the mnemonic, with 2048
# rounds and 64 bytes out. The salt is the fixed string of BIP39 and
# the passphrase, and FuguPass leaves the passphrase empty
# (KEY-MASTER-4).
BIP39_ROUNDS = 2048
BIP39_SALT = b"mnemonic"
ROOT_LEN = 64

# The bits of one word of a BIP39 mnemonic, and the bytes of the
# entropy of a mnemonic of 12 words: 128 bits, and then 4 bits of
# checksum (BIP39).
WORD_BITS = 11
CHILD_ENTROPY_LEN = 16

# The steps of a BIP85 path, and the fixed HMAC key of the DRNG
# (BIP85). The standard fixes the first step of every path, and each
# application fixes the steps after it. FuguPass takes the password
# of 21 characters, and the child mnemonic of 12 English words
# (KEY-BIP85-8).
BIP85_STEP = 83696968
BIP85_DRNG_KEY = b"bip-entropy-from-k"
PWD_BASE64_APP = 707764
PWD_BASE64_LEN = 21
BIP39_APP = 39
BIP39_ENGLISH = 0
BIP39_WORDS = 12

# The ten labels of the tree, in the order of the label table of
# spec/keys.md. Every label carries the prefix, and a label suffix
# stands directly after the label string. A slot index, an oracle
# index, a threshold and a coefficient index are unpadded decimal
# ASCII (KEY-DERIVE-2).
LABEL_ENTRY_KEY = "fugupass/v1/entry-key"
LABEL_DEVICE_FACTOR = "fugupass/v1/device-factor"
LABEL_CLIENT_KEY = "fugupass/v1/client-key"
LABEL_PIN_SALT = "fugupass/v1/pin-salt"
LABEL_WRAP = "fugupass/v1/wrap"
LABEL_SHAMIR = "fugupass/v1/shamir/"
LABEL_INDEX_KEY = "fugupass/v1/index-key"
LABEL_WRAP_INDEX = "fugupass/v1/wrap-index"
LABEL_CANARY_CHECK = "fugupass/v1/canary-check"
LABEL_PLATE_CHECK = "fugupass/v1/plate-check"

# The fixed test master of the tests. It is a public constant, and
# BIP39 publishes the seed of it as a test vector. The tests take the
# entry key of one slot, and slot 17 is that slot.
TEST_MASTER = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about")
TEST_SLOT = 17

# The machine name, the oracle index, and the canary form of the
# record suffix. The name holds lower-case letters, digits and
# hyphens (KEY-DEVICE-3). The oracle index counts from 1, and the
# canary form stands in place of the slot index (KEY-CLIENT-3,
# KEY-PIN-2).
TEST_MACHINE = "laptop-1"
TEST_ORACLE = 2
CANARY = "canary"

# The thresholds of the coefficient vectors. The coefficient label
# carries the threshold, so one threshold value proves nothing about
# another one (KEY-SHARE-3).
TEST_THRESHOLDS = (2, 3)

# The two masks of the vectors. They are public test constants, and
# they are not secrets. A real mask is the 32-byte answer of an
# oracle, and the client stores no mask (KEY-MASK-1, KEY-MASK-2). A
# test needs a fixed input, so these bytes stand in place of an
# answer.
TEST_MASK = bytes(range(32))
TEST_CANARY_MASK = bytes(range(32, 64))

# A public test material of the client key, above q - 1. A real
# t_ei above q - 1 is out of reach of a test, because q is close to
# 2^256. This constant takes the reduction of KEY-CLIENT-2 through
# the modulus, and not through the addition of 1 alone.
TEST_EDGE_MATERIAL = b"\xff" * 32

# The master of the test vectors of BIP85, and the BIP85 index of
# each of those vectors. The document names the master as one BIP32
# extended private key, and these 12 words give that key.
# _check_master() proves the words against the key.
BIP85_MASTER = (
    "install scatter logic circle pencil average "
    "fall shoe quantum disease suspect usage")
BIP85_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqF"
    "k2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
BIP85_SLOT = 0

# The bytes of a BIP32 extended key, and the two fields of it that
# this script reads. The body holds the version, the depth, the print
# of the parent, the child number, the chain code, and then the
# private key with one zero byte before it (BIP32).
XPRV_BYTES = 78
XPRV_CHAIN = slice(13, 45)
XPRV_KEY = slice(46, 78)

# The base58 alphabet of the BIP32 serialization. The digit zero and
# the letters O, I and l stay out of it.
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# The characters of one line of the header: the hex of 32 bytes, and
# the words of one part of a mnemonic.
HEX_WIDTH = 64
TEXT_WIDTH = 48

# The head and the tail of the generated header. The guard name
# differs from the guard of src/derive.h, because one test reads both
# files.
HEADER = f"""/*
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
 * The known-answer vectors of the derivation tree (TEST-KAT-1,
 * TEST-KAT-4). tests/vectors/generate.py made this file, and no
 * person edits it by hand:
 *
 *	python3 tests/vectors/generate.py > tests/vectors/derive.h
 *
 * The generator is a second implementation of the tree, and it takes
 * the Python standard library only. Two masters give the values.
 *
 * KAT_TEST_* comes from the fixed test master, a public constant of
 * the tests. BIP39 fixes root, and it publishes the seed of this
 * master as a test vector. The label table of spec/keys.md fixes
 * every label, and KEY-DERIVE-1 fixes f. These vectors cover each of
 * the ten labels of that table.
 *
 * KAT_TEST_MASK and KAT_TEST_CANARY_MASK are public test constants,
 * and they are not secrets. A real mask is the 32-byte answer of an
 * oracle, and the client stores no mask (KEY-MASK-1, KEY-MASK-2). A
 * test needs a fixed input, so these bytes stand in place of an
 * answer.
 *
 * KAT_BIP85_* comes from the master of the test vectors of BIP85.
 * That document prints the password and the child mnemonic beside
 * the path of each one, so a reader compares the two values below
 * with the document by eye. The document names the master as this
 * extended private key:
 *
 *	{BIP85_XPRV[:56]}
 *	{BIP85_XPRV[56:]}
 *
 * The 12 words of KAT_BIP85_MASTER give that key, and the generator
 * proves them against it at each run.
 *
 * A derived key stands as lower-case hex, with no separator and no
 * prefix. A master, a password and a mnemonic stand as text.
 */

#ifndef VECTORS_DERIVE_H
#define VECTORS_DERIVE_H
"""

FOOTER = "#endif /* VECTORS_DERIVE_H */"

# The SHA-256 of the word source below, as 64 lower-case hex
# characters. The digest covers the 2048 words, with one line feed
# after each word and no other byte. BIP39 fixes the list, FuguSeed
# pins this digest for it, and src/wordlist.h holds the same number.
WORDLIST_DIGEST = \
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

# The 2048 words of the BIP39 English list. The script holds the
# words, so it reads no file of the C build. _check_wordlist() proves
# this copy against the digest above.
WORDLIST = (
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
    "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford",
    "afraid", "again", "age", "agent", "agree", "ahead",
    "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow",
    "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused",
    "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology",
    "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow",
    "art", "artefact", "artist", "artwork", "ask", "aspect",
    "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away",
    "awesome", "awful", "awkward", "axis", "baby", "bachelor",
    "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach",
    "bean", "beauty", "because", "become", "beef", "before",
    "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame",
    "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board",
    "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick",
    "bridge", "brief", "bright", "bring", "brisk", "broccoli",
    "broken", "bronze", "broom", "brother", "brown", "brush",
    "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer",
    "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
    "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon",
    "card", "cargo", "carpet", "carry", "cart", "case",
    "cash", "casino", "castle", "casual", "cat", "catalog",
    "catch", "category", "cattle", "caught", "cause", "caution",
    "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change",
    "chaos", "chapter", "charge", "chase", "chat", "cheap",
    "check", "cheese", "chef", "cherry", "chest", "chicken",
    "chief", "child", "chimney", "choice", "choose", "chronic",
    "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify",
    "claw", "clay", "clean", "clerk", "clever", "click",
    "client", "cliff", "climb", "clinic", "clip", "clock",
    "clog", "close", "cloth", "cloud", "clown", "club",
    "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color",
    "column", "combine", "come", "comfort", "comic", "common",
    "company", "concert", "conduct", "confirm", "congress", "connect",
    "consider", "control", "convince", "cook", "cool", "copper",
    "copy", "coral", "core", "corn", "correct", "cost",
    "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram",
    "crane", "crash", "crater", "crawl", "crazy", "cream",
    "credit", "creek", "crew", "cricket", "crime", "crisp",
    "critic", "crop", "cross", "crouch", "crowd", "crucial",
    "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious",
    "current", "curtain", "curve", "cushion", "custom", "cute",
    "cycle", "dad", "damage", "damp", "dance", "danger",
    "daring", "dash", "daughter", "dawn", "day", "deal",
    "debate", "debris", "decade", "december", "decide", "decline",
    "decorate", "decrease", "deer", "defense", "define", "defy",
    "degree", "delay", "deliver", "demand", "demise", "denial",
    "dentist", "deny", "depart", "depend", "deposit", "depth",
    "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device",
    "devote", "diagram", "dial", "diamond", "diary", "dice",
    "diesel", "diet", "differ", "digital", "dignity", "dilemma",
    "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
    "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document",
    "dog", "doll", "dolphin", "domain", "donate", "donkey",
    "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress",
    "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during",
    "dust", "dutch", "duty", "dwarf", "dynamic", "eager",
    "eagle", "early", "earn", "earth", "easily", "east",
    "easy", "echo", "ecology", "economy", "edge", "edit",
    "educate", "effort", "egg", "eight", "either", "elbow",
    "elder", "electric", "elegant", "element", "elephant", "elevator",
    "elite", "else", "embark", "embody", "embrace", "emerge",
    "emotion", "employ", "empower", "empty", "enable", "enact",
    "end", "endless", "endorse", "enemy", "energy", "enforce",
    "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry",
    "envelope", "episode", "equal", "equip", "era", "erase",
    "erode", "erosion", "error", "erupt", "escape", "essay",
    "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust",
    "exhibit", "exile", "exist", "exit", "exotic", "expand",
    "expect", "expire", "explain", "expose", "express", "extend",
    "extra", "eye", "eyebrow", "fabric", "face", "faculty",
    "fade", "faint", "faith", "fall", "false", "fame",
    "family", "famous", "fan", "fancy", "fantasy", "farm",
    "fashion", "fat", "fatal", "father", "fatigue", "fault",
    "favorite", "feature", "february", "federal", "fee", "feed",
    "feel", "female", "fence", "festival", "fetch", "fever",
    "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fiscal", "fish",
    "fit", "fitness", "fix", "flag", "flame", "flash",
    "flat", "flavor", "flee", "flight", "flip", "float",
    "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow",
    "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found",
    "fox", "fragile", "frame", "frequent", "fresh", "friend",
    "fringe", "frog", "front", "frost", "frown", "frozen",
    "fruit", "fuel", "fun", "funny", "furnace", "fury",
    "future", "gadget", "gain", "galaxy", "gallery", "game",
    "gap", "garage", "garbage", "garden", "garlic", "garment",
    "gas", "gasp", "gate", "gather", "gauge", "gaze",
    "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe",
    "girl", "give", "glad", "glance", "glare", "glass",
    "glide", "glimpse", "globe", "gloom", "glory", "glove",
    "glow", "glue", "goat", "goddess", "gold", "good",
    "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass",
    "gravity", "great", "green", "grid", "grief", "grit",
    "grocery", "group", "grow", "grunt", "guard", "guess",
    "guide", "guilt", "guitar", "gun", "gym", "habit",
    "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have",
    "hawk", "hazard", "head", "health", "heart", "heavy",
    "hedgehog", "height", "hello", "helmet", "help", "hen",
    "hero", "hidden", "high", "hill", "hint", "hip",
    "hire", "history", "hobby", "hockey", "hold", "hole",
    "holiday", "hollow", "home", "honey", "hood", "hope",
    "horn", "horror", "horse", "hospital", "host", "hotel",
    "hour", "hover", "hub", "huge", "human", "humble",
    "humor", "hundred", "hungry", "hunt", "hurdle", "hurry",
    "hurt", "husband", "hybrid", "ice", "icon", "idea",
    "identify", "idle", "ignore", "ill", "illegal", "illness",
    "image", "imitate", "immense", "immune", "impact", "impose",
    "improve", "impulse", "inch", "include", "income", "increase",
    "index", "indicate", "indoor", "industry", "infant", "inflict",
    "inform", "inhale", "inherit", "initial", "inject", "injury",
    "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest",
    "into", "invest", "invite", "involve", "iron", "island",
    "isolate", "issue", "item", "ivory", "jacket", "jaguar",
    "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just",
    "kangaroo", "keen", "keep", "ketchup", "key", "kick",
    "kid", "kidney", "kind", "kingdom", "kiss", "kit",
    "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "lab", "label", "labor", "ladder",
    "lady", "lake", "lamp", "language", "laptop", "large",
    "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf",
    "learn", "leave", "lecture", "left", "leg", "legal",
    "legend", "leisure", "lemon", "lend", "length", "lens",
    "leopard", "lesson", "letter", "level", "liar", "liberty",
    "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list",
    "little", "live", "lizard", "load", "loan", "lobster",
    "local", "lock", "logic", "lonely", "long", "loop",
    "lottery", "loud", "lounge", "love", "loyal", "lucky",
    "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics",
    "machine", "mad", "magic", "magnet", "maid", "mail",
    "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble",
    "march", "margin", "marine", "market", "marriage", "mask",
    "mass", "master", "match", "material", "math", "matrix",
    "matter", "maximum", "maze", "meadow", "mean", "measure",
    "meat", "mechanic", "medal", "media", "melody", "melt",
    "member", "memory", "mention", "menu", "mercy", "merge",
    "merit", "merry", "mesh", "message", "metal", "method",
    "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery",
    "miss", "mistake", "mix", "mixed", "mixture", "mobile",
    "model", "modify", "mom", "moment", "monitor", "monkey",
    "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse",
    "move", "movie", "much", "muffin", "mule", "multiply",
    "muscle", "museum", "mushroom", "music", "must", "mutual",
    "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck",
    "need", "negative", "neglect", "neither", "nephew", "nerve",
    "nest", "net", "network", "neutral", "never", "news",
    "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note",
    "nothing", "notice", "novel", "now", "nuclear", "number",
    "nurse", "nut", "oak", "obey", "object", "oblige",
    "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often",
    "oil", "okay", "old", "olive", "olympic", "omit",
    "once", "one", "onion", "online", "only", "open",
    "opera", "opinion", "oppose", "option", "orange", "orbit",
    "orchard", "order", "ordinary", "organ", "orient", "original",
    "orphan", "ostrich", "other", "outdoor", "outer", "output",
    "outside", "oval", "oven", "over", "own", "owner",
    "oxygen", "oyster", "ozone", "pact", "paddle", "page",
    "pair", "palace", "palm", "panda", "panel", "panic",
    "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol",
    "pattern", "pause", "pave", "payment", "peace", "peanut",
    "pear", "peasant", "pelican", "pen", "penalty", "pencil",
    "people", "pepper", "perfect", "permit", "person", "pet",
    "phone", "photo", "phrase", "physical", "piano", "picnic",
    "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza",
    "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet",
    "point", "polar", "pole", "police", "pond", "pony",
    "pool", "popular", "portion", "position", "possible", "post",
    "potato", "pottery", "poverty", "powder", "power", "practice",
    "praise", "predict", "prefer", "prepare", "present", "pretty",
    "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce",
    "profit", "program", "project", "promote", "proof", "property",
    "prosper", "protect", "proud", "provide", "public", "pudding",
    "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push",
    "put", "puzzle", "pyramid", "quality", "quantum", "quarter",
    "question", "quick", "quit", "quiz", "quote", "rabbit",
    "raccoon", "race", "rack", "radar", "radio", "rail",
    "rain", "raise", "rally", "ramp", "ranch", "random",
    "range", "rapid", "rare", "rate", "rather", "raven",
    "raw", "razor", "ready", "real", "reason", "rebel",
    "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret",
    "regular", "reject", "relax", "release", "relief", "rely",
    "remain", "remember", "remind", "remove", "render", "renew",
    "rent", "reopen", "repair", "repeat", "replace", "report",
    "require", "rescue", "resemble", "resist", "resource", "response",
    "result", "retire", "retreat", "return", "reunion", "reveal",
    "review", "reward", "rhythm", "rib", "ribbon", "rice",
    "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival",
    "river", "road", "roast", "robot", "robust", "rocket",
    "romance", "roof", "rookie", "room", "rose", "rotate",
    "rough", "round", "route", "royal", "rubber", "rude",
    "rug", "rule", "run", "runway", "rural", "sad",
    "saddle", "sadness", "safe", "sail", "salad", "salmon",
    "salon", "salt", "salute", "same", "sample", "sand",
    "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme",
    "school", "science", "scissors", "scorpion", "scout", "scrap",
    "screen", "script", "scrub", "sea", "search", "season",
    "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior",
    "sense", "sentence", "series", "service", "session", "settle",
    "setup", "seven", "shadow", "shaft", "shallow", "share",
    "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle",
    "shy", "sibling", "sick", "side", "siege", "sight",
    "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate",
    "six", "size", "skate", "sketch", "ski", "skill",
    "skin", "skirt", "skull", "slab", "slam", "sleep",
    "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile",
    "smoke", "smooth", "snack", "snake", "snap", "sniff",
    "snow", "soap", "soccer", "social", "sock", "soda",
    "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare",
    "spatial", "spawn", "speak", "special", "speed", "spell",
    "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport",
    "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage",
    "stairs", "stamp", "stand", "start", "state", "stay",
    "steak", "steel", "stem", "step", "stereo", "stick",
    "still", "sting", "stock", "stomach", "stone", "stool",
    "story", "stove", "strategy", "street", "strike", "strong",
    "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer",
    "sugar", "suggest", "suit", "summer", "sun", "sunny",
    "sunset", "super", "supply", "supreme", "sure", "surface",
    "surge", "surprise", "surround", "survey", "suspect", "sustain",
    "swallow", "swamp", "swap", "swarm", "swear", "sweet",
    "swift", "swim", "swing", "switch", "sword", "symbol",
    "symptom", "syrup", "system", "table", "tackle", "tag",
    "tail", "talent", "talk", "tank", "tape", "target",
    "task", "taste", "tattoo", "taxi", "teach", "team",
    "tell", "ten", "tenant", "tennis", "tent", "term",
    "test", "text", "thank", "that", "theme", "then",
    "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket",
    "tide", "tiger", "tilt", "timber", "time", "tiny",
    "tip", "tired", "tissue", "title", "toast", "tobacco",
    "today", "toddler", "toe", "together", "toilet", "token",
    "tomato", "tomorrow", "tone", "tongue", "tonight", "tool",
    "tooth", "top", "topic", "topple", "torch", "tornado",
    "tortoise", "toss", "total", "tourist", "toward", "tower",
    "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray",
    "treat", "tree", "trend", "trial", "tribe", "trick",
    "trigger", "trim", "trip", "trophy", "trouble", "truck",
    "true", "truly", "trumpet", "trust", "truth", "try",
    "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin",
    "twist", "two", "type", "typical", "ugly", "umbrella",
    "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit",
    "universe", "unknown", "unlock", "until", "unusual", "unveil",
    "update", "upgrade", "uphold", "upon", "upper", "upset",
    "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor",
    "various", "vast", "vault", "vehicle", "velvet", "vendor",
    "venture", "venue", "verb", "verify", "version", "very",
    "vessel", "veteran", "viable", "vibrant", "vicious", "victory",
    "video", "view", "village", "vintage", "violin", "virtual",
    "virus", "visa", "visit", "visual", "vital", "vivid",
    "vocal", "voice", "void", "volcano", "volume", "vote",
    "voyage", "wage", "wagon", "wait", "walk", "wall",
    "walnut", "want", "warfare", "warm", "warrior", "wash",
    "wasp", "waste", "water", "wave", "way", "wealth",
    "weapon", "wear", "weasel", "weather", "web", "wedding",
    "weekend", "weird", "welcome", "west", "wet", "whale",
    "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will",
    "win", "window", "wine", "wing", "wink", "winner",
    "winter", "wire", "wisdom", "wise", "wish", "witness",
    "wolf", "woman", "wonder", "wood", "wool", "word",
    "work", "world", "worry", "worth", "wrap", "wreck",
    "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero",
    "zone", "zoo",
)


def _fail(message):
    """Stop the run, and report the message on the error output."""
    raise SystemExit("generate.py: " + message)


def _f(key, label):
    """f(key, label): HMAC-SHA256, with 32 bytes out (KEY-DERIVE-1)."""
    return hmac.new(key, label.encode(), hashlib.sha256).digest()


def bip39_seed(mnemonic):
    """root: the BIP39 seed of the mnemonic, with no passphrase."""
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode(), BIP39_SALT, BIP39_ROUNDS, ROOT_LEN)


def bip39_mnemonic(entropy):
    """The BIP39 mnemonic of the entropy, as one line of words.

    Each word carries 11 bits. The checksum follows the bits of the
    entropy, and it holds one bit for each 32 bits of it. The
    checksum bits are the first bits of the SHA-256 of the entropy.
    """
    bits = "".join(f"{byte:08b}" for byte in entropy)
    sum_bits = len(entropy) * 8 // 32
    bits += f"{hashlib.sha256(entropy).digest()[0]:08b}"[:sum_bits]
    return " ".join(
        WORDLIST[int(bits[at:at + WORD_BITS], 2)]
        for at in range(0, len(bits), WORD_BITS))


def bip32_master(root):
    """The BIP32 master of root: a private key, and a chain code."""
    total = hmac.new(BIP32_MASTER_KEY, root, hashlib.sha512).digest()
    key = int.from_bytes(total[:32], "big")
    if key == 0 or key >= GROUP_ORDER:
        _fail("the curve rejects the master key")
    return key, total[32:]


def bip32_hardened(key, chain, index):
    """One hardened BIP32 step, from the parent key and chain code.

    The message holds one zero byte, the private key of the parent,
    and the index. The index is big-endian, and it carries the
    hardened bit. The chain code of the parent is the key of the
    HMAC. The private key of the child is the sum of the parent key
    and the first half of the result, modulo the order of the group.
    """
    data = b"\x00" + key.to_bytes(32, "big")
    data += (index | HARDENED).to_bytes(4, "big")
    total = hmac.new(chain, data, hashlib.sha512).digest()
    tweak = int.from_bytes(total[:32], "big")
    if tweak >= GROUP_ORDER:
        _fail(f"the curve rejects the step of index {index}")
    child = (key + tweak) % GROUP_ORDER
    if child == 0:
        _fail(f"the child key of index {index} is zero")
    return child, total[32:]


def bip85_entropy(root, path):
    """The 64 bytes of the BIP85 DRNG, at the path from root.

    No index of path carries the hardened bit, and this function
    hardens every step. The DRNG is HMAC-SHA512 over the private key
    of the last step, with the fixed key of BIP85.
    """
    key, chain = bip32_master(root)
    for index in path:
        key, chain = bip32_hardened(key, chain, index)
    return hmac.new(
        BIP85_DRNG_KEY, key.to_bytes(32, "big"), hashlib.sha512).digest()


def bip85_pwd_base64(root, slot):
    """The BIP85 PWD BASE64 password of the slot index (KEY-BIP85-1).

    The password is the first 21 characters of the Base64 text of
    the 64 bytes of the DRNG.
    """
    path = (BIP85_STEP, PWD_BASE64_APP, PWD_BASE64_LEN, slot)
    text = base64.b64encode(bip85_entropy(root, path)).decode()
    return text[:PWD_BASE64_LEN]


def bip85_bip39(root, slot):
    """The BIP85 child mnemonic of the slot index (KEY-BIP85-2).

    The mnemonic takes the first 16 bytes of the DRNG: 128 bits for
    12 words of the English list.
    """
    path = (BIP85_STEP, BIP39_APP, BIP39_ENGLISH, BIP39_WORDS, slot)
    entropy = bip85_entropy(root, path)[:CHILD_ENTROPY_LEN]
    return bip39_mnemonic(entropy)


def entry_key(root, slot):
    """The entry key of the slot index (KEY-ENTRY-2)."""
    return _f(root, LABEL_ENTRY_KEY + str(slot))


def plate_check(root):
    """The plate check value of root (KEY-MASTER-5)."""
    return _f(root, LABEL_PLATE_CHECK)


def device_factor(root, machine):
    """X: the device factor of one machine name (KEY-DEVICE-1)."""
    return _f(root, LABEL_DEVICE_FACTOR + machine)


def record_suffix(oracle, slot):
    """The per-record suffix i/e, or i/canary (spec/keys.md)."""
    return f"{oracle}/{slot}"


def client_material(factor, suffix):
    """t_ei: the client key material of one record (KEY-CLIENT-1)."""
    return _f(factor, LABEL_CLIENT_KEY + suffix)


def client_key(material):
    """ck_ei: (t_ei mod (q - 1)) + 1, as 32 bytes (KEY-CLIENT-2).

    The reduction holds the key in the range 1 to q - 1. Python
    reads the material as one big-endian integer, so the script
    needs no library of big numbers.
    """
    number = int.from_bytes(material, "big") % (GROUP_ORDER - 1) + 1
    return number.to_bytes(32, "big")


def pin_salt(factor, suffix):
    """salt_ei: the pin salt of one record (KEY-PIN-2)."""
    return _f(factor, LABEL_PIN_SALT + suffix)


def wrap_key(mask, suffix):
    """wk_ei: the wrap key of one record, from its mask (KEY-MASK-3)."""
    return _f(mask, LABEL_WRAP + suffix)


def index_key(root):
    """K_idx: the key of the index file (KEY-MASK-6)."""
    return _f(root, LABEL_INDEX_KEY)


def index_wrap_key(mask, oracle):
    """The index wrap key of one oracle (KEY-MASK-7).

    The key comes from the canary mask of that oracle.
    """
    return _f(mask, LABEL_WRAP_INDEX + str(oracle))


def canary_check_key(mask, oracle):
    """The seal key of the canary check of one oracle (KEY-MASK-5).

    The key comes from the canary mask of that oracle.
    """
    return _f(mask, LABEL_CANARY_CHECK + str(oracle))


def coefficient(secret, threshold, index):
    """A_j: coefficient j of one split, at the threshold (KEY-SHARE-3)."""
    return _f(secret, f"{LABEL_SHAMIR}{threshold}/{index}")


def _base58_decode(text):
    """The body of the base58 text, with the 4 check bytes proven.

    An extended key starts with a version byte that is not zero, so
    this decoder needs no rule for a leading zero byte.
    """
    number = 0
    for character in text:
        number = number * 58 + BASE58.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        _fail("the check bytes of the extended key are bad")
    return body


def _check_master(root):
    """Prove root against the extended key of the BIP85 document.

    The document names its master as one extended private key only.
    The C takes root, so this script takes the 12 words of that
    master. This proof ties the two forms together.
    """
    body = _base58_decode(BIP85_XPRV)
    if len(body) != XPRV_BYTES:
        _fail(f"the extended key holds {len(body)} bytes")
    key, chain = bip32_master(root)
    if chain != body[XPRV_CHAIN] or key.to_bytes(32, "big") != body[XPRV_KEY]:
        _fail("the BIP85 master words do not give that extended key")


def _check_wordlist():
    """Prove the word list of this script against the pinned digest."""
    source = "".join(word + "\n" for word in WORDLIST)
    digest = hashlib.sha256(source.encode()).hexdigest()
    if len(WORDLIST) != 2048 or digest != WORDLIST_DIGEST:
        _fail("the word list does not carry the pinned digest")


def _hex_parts(value):
    """The lower-case hex of the bytes, in parts of 32 bytes."""
    text = value.hex()
    return [text[at:at + HEX_WIDTH] for at in range(0, len(text), HEX_WIDTH)]


def _text_parts(text):
    """The text, in parts of TEXT_WIDTH characters or fewer.

    A part breaks after a space, so each part holds whole words. The
    parts join back to the text, because each part but the last one
    keeps its trailing space.
    """
    parts = [""]
    for word in text.split(" "):
        if parts[-1] and len(parts[-1]) + len(word) > TEXT_WIDTH:
            parts.append("")
        parts[-1] += word + " "
    parts[-1] = parts[-1][:-1]
    return parts


def _define(name, value):
    """Print one #define of a name and a plain value."""
    print(f"#define {name}\t{value}")


def _define_text(name, parts):
    """Print one #define of a C string, with one part on each line.

    The C joins the parts, because two string parts beside each
    other are one string. Each part therefore keeps its line inside
    80 columns.
    """
    print(f"#define {name} \\")
    for at, part in enumerate(parts):
        tail = "" if at + 1 == len(parts) else " \\"
        print(f"\t\"{part}\"{tail}")


def _print_custody(root, secret):
    """Compute and print the custody vectors (TEST-KAT-4).

    The values come from the fixed test master, the fixed machine
    name, and the two public test masks. The coefficients split the
    secret, and the caller passes the entry key of the test slot.
    """
    entry = record_suffix(TEST_ORACLE, TEST_SLOT)
    canary = record_suffix(TEST_ORACLE, CANARY)
    factor = device_factor(root, TEST_MACHINE)
    material = client_material(factor, entry)
    key = client_key(material)
    canary_key = client_key(client_material(factor, canary))
    edge_key = client_key(TEST_EDGE_MATERIAL)
    for name, value in (("client", key), ("canary", canary_key),
                        ("edge", edge_key)):
        if not 1 <= int.from_bytes(value, "big") < GROUP_ORDER:
            _fail(f"the {name} key falls outside the range of the curve")
    if int.from_bytes(edge_key, "big") >= int.from_bytes(
            TEST_EDGE_MATERIAL, "big"):
        _fail("the edge material takes no reduction")

    print("/* The machine name of the device factor below"
          " (KEY-DEVICE-3). */")
    _define_text("KAT_TEST_MACHINE", _text_parts(TEST_MACHINE))
    print()
    print("/* The device factor: f(root, "
          f"\"{LABEL_DEVICE_FACTOR}{TEST_MACHINE}\"). */")
    _define_text("KAT_TEST_DEVICE_FACTOR", _hex_parts(factor))
    print()
    print("/* The oracle index of the record vectors below. */")
    _define("KAT_TEST_ORACLE", TEST_ORACLE)
    print()
    print("/* The client key material: f(X, "
          f"\"{LABEL_CLIENT_KEY}{entry}\"). */")
    _define_text("KAT_TEST_CLIENT_MATERIAL", _hex_parts(material))
    print()
    print("/* The client key of that material: (t mod (q - 1)) + 1. */")
    _define_text("KAT_TEST_CLIENT_KEY", _hex_parts(key))
    print()
    print("/*")
    print(" * The canary client key: the same reduction of")
    print(f" * f(X, \"{LABEL_CLIENT_KEY}{canary}\").")
    print(" */")
    _define_text("KAT_TEST_CANARY_CLIENT_KEY", _hex_parts(canary_key))
    print()
    print("/* A public test material of 32 bytes 0xff, above"
          " q - 1. */")
    _define_text("KAT_TEST_EDGE_MATERIAL", _hex_parts(TEST_EDGE_MATERIAL))
    print()
    print("/* The client key of that material, through the"
          " modulus. */")
    _define_text("KAT_TEST_EDGE_CLIENT_KEY", _hex_parts(edge_key))
    print()
    print(f"/* The pin salt: f(X, \"{LABEL_PIN_SALT}{entry}\"). */")
    _define_text("KAT_TEST_PIN_SALT", _hex_parts(pin_salt(factor, entry)))
    print()
    print("/* The canary pin salt: f(X, "
          f"\"{LABEL_PIN_SALT}{canary}\"). */")
    _define_text(
        "KAT_TEST_CANARY_PIN_SALT", _hex_parts(pin_salt(factor, canary)))
    print()
    print("/* A public test mask of the record, in place of an"
          " answer. */")
    _define_text("KAT_TEST_MASK", _hex_parts(TEST_MASK))
    print()
    print("/* A public test mask of the canary record. */")
    _define_text("KAT_TEST_CANARY_MASK", _hex_parts(TEST_CANARY_MASK))
    print()
    print("/* The wrap key: f(mask, "
          f"\"{LABEL_WRAP}{entry}\"). */")
    _define_text(
        "KAT_TEST_WRAP_KEY", _hex_parts(wrap_key(TEST_MASK, entry)))
    print()
    print(f"/* The index key: f(root, \"{LABEL_INDEX_KEY}\"). */")
    _define_text("KAT_TEST_INDEX_KEY", _hex_parts(index_key(root)))
    print()
    print("/* The index wrap key: f(canary mask, "
          f"\"{LABEL_WRAP_INDEX}{TEST_ORACLE}\"). */")
    _define_text(
        "KAT_TEST_INDEX_WRAP_KEY",
        _hex_parts(index_wrap_key(TEST_CANARY_MASK, TEST_ORACLE)))
    print()
    print("/*")
    print(" * The canary check seal key:")
    print(f" * f(canary mask, \"{LABEL_CANARY_CHECK}{TEST_ORACLE}\").")
    print(" */")
    _define_text(
        "KAT_TEST_CANARY_CHECK_KEY",
        _hex_parts(canary_check_key(TEST_CANARY_MASK, TEST_ORACLE)))
    print()
    print("/*")
    print(" * The coefficients of the split of KAT_TEST_ENTRY_KEY")
    print(" * (KEY-SHARE-3). A name carries the threshold and the")
    print(" * coefficient index, as the label does:")
    print(" * KAT_TEST_COEFF_K3_1 comes from")
    print(f" * f(K_e, \"{LABEL_SHAMIR}3/1\").")
    print(" */")
    for threshold in TEST_THRESHOLDS:
        for index in range(1, threshold):
            _define_text(
                f"KAT_TEST_COEFF_K{threshold}_{index}",
                _hex_parts(coefficient(secret, threshold, index)))
            print()


def main():
    """Prove the data of the script, and print the header."""
    _check_wordlist()
    test_root = bip39_seed(TEST_MASTER)
    test_entry_key = entry_key(test_root, TEST_SLOT)
    test_plate_check = plate_check(test_root)
    bip85_root = bip39_seed(BIP85_MASTER)
    _check_master(bip85_root)
    password = bip85_pwd_base64(bip85_root, BIP85_SLOT)
    child = bip85_bip39(bip85_root, BIP85_SLOT)
    if len(password) != PWD_BASE64_LEN:
        _fail(f"the password holds {len(password)} characters")
    if len(child.split(" ")) != BIP39_WORDS:
        _fail("the child mnemonic holds a wrong count of words")

    print(HEADER)
    print("/* The fixed test master: 12 words of the BIP39 English list. */")
    _define_text("KAT_TEST_MASTER", _text_parts(TEST_MASTER))
    print()
    print("/* root of the test master: its BIP39 seed, with no"
          " passphrase. */")
    _define_text("KAT_TEST_ROOT", _hex_parts(test_root))
    print()
    print("/* The slot index of the entry key below. */")
    _define("KAT_TEST_SLOT", TEST_SLOT)
    print()
    print("/* The entry key of that slot: f(root, "
          f"\"{LABEL_ENTRY_KEY}{TEST_SLOT}\"). */")
    _define_text("KAT_TEST_ENTRY_KEY", _hex_parts(test_entry_key))
    print()
    print(f"/* The plate check value: f(root, \"{LABEL_PLATE_CHECK}\"). */")
    _define_text("KAT_TEST_PLATE_CHECK", _hex_parts(test_plate_check))
    print()
    _print_custody(test_root, test_entry_key)
    print("/* The 12 words of the master of the BIP85 test vectors. */")
    _define_text("KAT_BIP85_MASTER", _text_parts(BIP85_MASTER))
    print()
    print("/* root of the BIP85 master: its BIP39 seed, with no"
          " passphrase. */")
    _define_text("KAT_BIP85_ROOT", _hex_parts(bip85_root))
    print()
    print("/* The BIP85 index of the two vectors below. */")
    _define("KAT_BIP85_SLOT", BIP85_SLOT)
    print()
    print("/* PWD BASE64, at m/83696968'/707764'/21'/0'. */")
    _define_text("KAT_BIP85_PWD", _text_parts(password))
    print()
    print("/* BIP39, at m/83696968'/39'/0'/12'/0'. */")
    _define_text("KAT_BIP85_MNEMONIC", _text_parts(child))
    print()
    print(FOOTER)


if __name__ == "__main__":
    main()
