# mk/local.mk: the consumer hook of this repository (MK-LOCAL).
# sync never touches this file.

# The Perl sources of this repository: the interface program in bin/,
# the tests in t/, the build step of the unveil list at
# src/unveil-paths, and the stub directory tests/stubs
# (PROG-SPLIT-7, PROG-SPLIT-10). find(1) takes a file as a root, so
# the list names the build step directly. src/ and tests/ hold more
# Perl, and these two paths keep it outside the gates.
#
# lib/ holds the rules file of the perl pack and no module. This
# repository ships no CPAN distribution, so the dist target of that
# pack stays unused, and the rules of lib/CLAUDE.md hold for the
# sources above.
PERL_SRC_DIRS	= bin t src/unveil-paths tests/stubs

# The full test tier set of make test
TEST_GLOBS	= t/fugupass/*.t t/ci/*.t

# The interop harness (TEST-HARNESS-1). It needs a live counterparty
# and an OpenBSD guest, so no CHECK_TARGETS line and no TEST_GLOBS
# entry names it, and make check never runs it. tests/harness states
# the environment that the operator gives it.
HARNESS		= tests/harness

harness:
	@$(HARNESS)

.PHONY: harness
