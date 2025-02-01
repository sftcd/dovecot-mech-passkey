auth_moduledir = $(moduledir)/auth

auth_module_LTLIBRARIES = \
	libmech_passkey.la

libmech_passkey_la_LDFLAGS = -module -avoid-version
libmech_passkey_la_LIBADD = $(LIBDOVECOT) \
	$(CBOR_LIBS) \
	$(FIDO2_LIBS)
libmech_passkey_la_CPPFLAGS = $(AM_CPPFLAGS) \
      $(DOVECOT_CFLAGS) \
      $(LIBDOVECOT_INCLUDE) \
      $(LIBDOVECOT_AUTH_INCLUDE) \
      $(CBOR_CFLAGS) \
      $(FIDO2_CFLAGS)
libmech_passkey_la_SOURCES = mech-passkey.c
