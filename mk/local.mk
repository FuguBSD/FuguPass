# mk/local.mk: the consumer hook of this repository (MK-LOCAL).
# sync never touches this file.

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
