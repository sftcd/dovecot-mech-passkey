#pragma clang diagnostic ignored "-Wunused-parameter"

#include "lib.h"
#include "mech.h"
#include "array.h"
#include "randgen.h"
#include "buffer.h"
#include "dcrypt.h"
#include "byteorder.h"
#include "guid.h"
#include "base64.h"

#include "cbor.h"
#include "cbor/data.h"
#include "cbor/strings.h"
#include "cbor/ints.h"
#include "cbor/bytestrings.h"
#include "cbor/serialization.h"

const char *mech_passkey_plugin_version = DOVECOT_ABI_VERSION;
const char *mech_passkey_plugin_dependencies[] = { NULL };

#define PASSKEY_SCHEME "PASSKEY"

struct passkey_fido_cred {
	unsigned char aaguid[16];
	buffer_t *key_id;
	struct dcrypt_public_key *pubkey;
};

struct passkey_auth_request {
	struct auth_request auth_request;
	struct passkey_fido_cred cred;
	buffer_t *cd; /* client data */

	bool have_user:1;
};

static struct auth_request *mech_passkey_auth_new(void)
{
	struct passkey_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"passkey_auth_request", 2048);
	request = p_new(pool, struct passkey_auth_request, 1);
	request->auth_request.pool = pool;
	return &request->auth_request;
}

struct cbor_decode_context {
};

#define PASSKEY_CBOR_INT(s, typ) \
static void passkey_cbor_uint##s(void *context, typ v) \
{ \
	uint64_t v2 = v; \
	i_debug("Got " #typ " value %lu", v2); \
}; \
static void passkey_cbor_negint##s(void *context, typ v) \
{ \
	uint64_t v2 = v; \
	i_debug("Got " #typ " value -%lu", v2); \
}

PASSKEY_CBOR_INT(8, uint8_t);
PASSKEY_CBOR_INT(16, uint16_t);
PASSKEY_CBOR_INT(32, uint32_t);
PASSKEY_CBOR_INT(64, uint64_t);

static void passkey_cbor_map_start(void *context, unsigned long size)
{
	i_debug("map of %zu values", size);
}

static void passkey_cbor_tag(void *context, unsigned long tag)
{
	i_debug("got tag %zu", tag);
}

static void passkey_cbor_string(void *context, const unsigned char *string, unsigned long size)
{
	i_debug("got string %zu bytes", size);
}

static int passkey_decode_public_key(const unsigned char *ptr, size_t size)
{
	struct cbor_decode_context ctx;
	struct cbor_decoder_result res;

	struct cbor_callbacks cb = cbor_empty_callbacks;

	cb.map_start = passkey_cbor_map_start;
	cb.tag = passkey_cbor_tag;
	cb.string = passkey_cbor_string;
	cb.byte_string = passkey_cbor_string;

	cb.negint8 = passkey_cbor_negint8;
	cb.negint16 = passkey_cbor_negint16;
	cb.negint32 = passkey_cbor_negint32;
	cb.negint64 = passkey_cbor_negint64;

	cb.uint8 = passkey_cbor_uint8;
	cb.uint16 = passkey_cbor_uint16;
	cb.uint32 = passkey_cbor_uint32;
	cb.uint64 = passkey_cbor_uint64;

	res = cbor_stream_decode(ptr, size, &cb, &ctx);

	if (res.status != CBOR_DECODER_FINISHED)
		return -1;

	return res.read;
}

#define ADVANCE(n) ptr += n; size -= n

static bool passkey_fido_parse_creds(struct passkey_auth_request *preq,
				     const unsigned char *credentials, size_t size,
				     const char **error_r)
{
	bool have_more_cred = TRUE;
	const unsigned char *ptr = credentials;

	while (have_more_cred) {
		/* first we have GUID */
		memcpy(preq->cred.aaguid, ptr, 16);
		/* then get cred id size */
		ADVANCE(16);
		i_debug("got guid %s", guid_128_to_uuid_string(preq->cred.aaguid, FORMAT_RECORD));
		uint16_t cred_size = be16_to_cpu_unaligned(ptr);
		if (cred_size > size) {
			*error_r = t_strdup_printf("too large size (%u)", cred_size);
			return FALSE;
		}
		ADVANCE(2);
		preq->cred.key_id = buffer_create_dynamic(preq->auth_request.pool, cred_size);
		memcpy(preq->cred.key_id, ptr, cred_size);
		ADVANCE(cred_size);
		/* CBOR decode rest */
		passkey_decode_public_key(ptr, size);
		have_more_cred = FALSE;
	}

	return TRUE;
}

/*static void passkey_cbor_add_bool(cbor_item_t *map, const char *key, bool value)
{
	struct cbor_pair pair = {
		.key = cbor_build_string(key),
		.value = cbor_build_bool(value),
	};

	cbor_map_add(map, pair);
}*/

static void passkey_cbor_add_string(cbor_item_t *map, const char *key, const char *value)
{
	struct cbor_pair pair = {
		.key = cbor_build_string(key),
		.value = cbor_build_string(value),
	};

	cbor_map_add(map, pair);
}

static void passkey_cbor_add_buffer(cbor_item_t *map, const char *key, buffer_t *buf)
{
	struct cbor_pair pair = {
		.key = cbor_build_string(key),
		.value = cbor_build_bytestring(buf->data, buf->used),
	};

	cbor_map_add(map, pair);
}

static void passkey_cbor_add_ulong(cbor_item_t *map, const char *key, unsigned long value)
{
	struct cbor_pair pair = {
		.key = cbor_build_string(key),
		.value = cbor_build_uint64(value),
	};

	cbor_map_add(map, pair);
}

static void
passkey_lookup_credentials_callback(enum passdb_result result,
				    const unsigned char *credentials, size_t size,
				    struct auth_request *req)
{
	const char *error;
	struct passkey_auth_request *preq =
		container_of(req, struct passkey_auth_request, auth_request);

	if (result != PASSDB_RESULT_OK) {
		e_error(req->mech_event, "cred lookup failed");
		auth_request_fail(req);
		return;
	}

	buffer_t *creds = t_buffer_create(MAX_BASE64_DECODED_SIZE(size));
	base64_decode(credentials, size, creds);

	/* parse credentials */
	bool success = passkey_fido_parse_creds(preq, creds->data, creds->used, &error);

	if (!success) {
		e_error(req->mech_event, "Cannot parse credentials: %s", error);
		auth_request_internal_failure(req);
	} else {
		/* create client data */
		preq->cd = t_buffer_create(64);
		unsigned char *fillbuf = buffer_get_space_unsafe(preq->cd, 0, 64);
		random_fill(fillbuf, 64);

		/* build a request */
		cbor_item_t *root = cbor_new_definite_map(4);
		passkey_cbor_add_string(root, "userVerification", "required");
		passkey_cbor_add_string(root, "rpId", "imap://localhost");
		passkey_cbor_add_buffer(root, "challenge", preq->cd);
		passkey_cbor_add_ulong(root, "timeout", 60000);

		buffer_t *tmp = t_buffer_create(256);
		fillbuf = buffer_get_space_unsafe(tmp, 0, 256);
		size_t used = cbor_serialize_map(root, fillbuf, 256);
		buffer_set_used_size(tmp, used);

		preq->have_user = TRUE;
		auth_request_continue(req, tmp->data, tmp->used);
	}
}

static void
mech_passkey_auth_continue(struct auth_request *req,
			   const unsigned char *data, size_t data_len)
{
	const char *error;
	struct passkey_auth_request *preq =
		container_of(req, struct passkey_auth_request, auth_request);

	if (data_len == 0) {
		auth_request_fail(req);
		return;
	}

	if (!preq->have_user) {
		const char *username = t_strndup(data, data_len);
		if (!auth_request_set_username(req, username, &error)) {
			e_error(req->mech_event, "Invalid username: %s", error);
			auth_request_fail(req);
			return;
		}
		auth_request_lookup_credentials(req, PASSKEY_SCHEME,
						passkey_lookup_credentials_callback);
	}
}

static void mech_passkey_auth_free(struct auth_request *_request)
{
	struct passkey_auth_request *preq =
		container_of(_request, struct passkey_auth_request, auth_request);

	/* free all credentials */
	pool_unref(&preq->auth_request.pool);
}

static const struct mech_module mech_passkey_module = {
	.mech_name = "PASSKEY",
	.flags = MECH_SEC_ALLOW_NULS,
	.passdb_need = MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,

	.auth_new = mech_passkey_auth_new,
	.auth_free = mech_passkey_auth_free,
	.auth_initial = mech_generic_auth_initial,
	.auth_continue = mech_passkey_auth_continue,
};

void mech_passkey_init(void);
void mech_passkey_deinit(void);

static const struct password_scheme scheme_passkey =
{
	.name = "PASSKEY",
};

void mech_passkey_init(void)
{
	mech_register_module(&mech_passkey_module);
	password_scheme_register(&scheme_passkey);
}

void mech_passkey_deinit(void)
{
	mech_unregister_module(&mech_passkey_module);
}
