AM_CPPFLAGS = $(DOVECOT_CFLAGS) \
      $(LIBDOVECOT_INCLUDE) \
      $(LIBDOVECOT_AUTH_INCLUDE) \
      $(CBOR_CFLAGS) \
      $(FIDO2_CFLAGS) -ggdb3 -O0 -Wno-error -Wno-unused

auth_moduledir = $(moduledir)/auth

auth_module_LTLIBRARIES = \
	libmech_passkey.la

libmech_passkey_la_LDFLAGS = -module -avoid-version
libmech_passkey_la_LIBADD = $(LIBDOVECOT) \
	$(CBOR_LIBS) \
	$(FIDO2_LIBS)
libmech_passkey_la_SOURCES = mech-passkey.c

noinst_PROGRAMS = test

test_SOURCES = test.c mech.c
test_CFLAGS = $(AM_CPPFLAGS) $(DOVECOT_BINARY_CFLAGS) -Wno-error -ggdb3 -O0
test_LDFLAGS = $(DOVECOT_BINARY_LDFLAGS)
test_LDADD = libmech_passkey.la $(LIBDOVECOT) $(CBOR_LIBS) $(FIDO2_LIBS)
