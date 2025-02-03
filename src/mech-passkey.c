#pragma clang diagnostic ignored "-Wunused-parameter"

#include "lib.h"
#include "mech.h"
#include "array.h"
#include "randgen.h"
#include "buffer.h"
#include "str.h"
#include "dcrypt.h"
#include "byteorder.h"
#include "guid.h"
#include "base64.h"
#include "sha2.h"

#include "hex-binary.h"

#include "cbor.h"

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

static int passkey_decode_public_key(struct passkey_auth_request *preq,
				     const unsigned char *ptr, size_t size)
{
	struct cbor_load_result result;
	cbor_item_t *item = cbor_load(ptr, size, &result);
	const void *xb = NULL;
	size_t xl = 0;
	const void *yb = NULL;
	size_t yl = 0;
	if (result.error.code != 0)
		return -1;
	if (cbor_isa_map(item)) {
		size_t items = cbor_map_size(item);
		struct cbor_pair *pairs = cbor_map_handle(item);
		int key_type;
		int algorithm;
		int curve;

		for (size_t i = 0; i < items; i++) {
			struct cbor_pair *pair = pairs + i;
			int key;
			cbor_type type = cbor_typeof(item);
			i_debug("item is %d", type);
			key = cbor_get_uint8(pair->key);
			if (cbor_isa_negint(pair->key))
				key = (-key)-1;
			i_debug("key is %d", key);
			switch (key) {
			case 1: /* Key type */
				key_type = cbor_get_int(pair->value);
				i_debug("Key type = %d", key_type);
				break;
			case 3:
				algorithm = cbor_get_uint8(pair->value);
				if (cbor_isa_negint(pair->value))
						algorithm = (-algorithm)-1;
				i_debug("algorithm = %d", algorithm);
				break;
			case -1:
				curve = cbor_get_uint8(pair->value);
				if (cbor_isa_negint(pair->value))
					curve = (-curve)-1;
				i_debug("curve = %d", curve);
				break;
			case -2:
				xl = cbor_bytestring_length(pair->value);
				xb = cbor_bytestring_handle(pair->value);
				i_debug("x = %zu bytes", xl);
				break;
			case -3:
				yl = cbor_bytestring_length(pair->value);
				yb = cbor_bytestring_handle(pair->value);
				i_debug("y = %zu bytes", yl);
				break;
			}
		}
	}

	const char *error;
	ARRAY_TYPE(dcrypt_raw_key) params;
	t_array_init(&params, 3);
	struct dcrypt_raw_key *elem = array_append_space(&params);
	static const unsigned char oid[] = {
		'\x06','\x08','*','\x86','H','\xce','=','\x03','\x01','\x07'
	};
	elem->parameter = oid;
	elem->len = sizeof(oid);
	elem = array_append_space(&params);
	buffer_t *tmp = t_buffer_create(xl+yl+1);
	buffer_append_c(tmp, '\x04');
	buffer_append(tmp, xb, xl);
	buffer_append(tmp, yb, yl);
	elem->parameter = tmp->data;
	elem->len = tmp->used;

	if (!dcrypt_key_load_public_raw(&preq->cred.pubkey, DCRYPT_KEY_EC, &params, &error))
		i_debug("%s", error);

	cbor_decref(&item);
	return result.read;
}

#define ADVANCE(n) { \
	if ((n) > size) { \
		*error_r = "Truncated credential"; \
		return FALSE; \
	} \
	ptr += (n); size -= (n); \
}

static bool passkey_fido_parse_creds(struct passkey_auth_request *preq,
				     const unsigned char *credentials, size_t size,
				     const char **error_r)
{
	bool have_more_cred = TRUE;
	const unsigned char *ptr = credentials;

	if (size < 128) {
		*error_r = "Too short credential";
		return FALSE;
	}

	while (have_more_cred) {
		/* first we have GUID */
		memcpy(preq->cred.aaguid, ptr, 16);
		/* then get cred id size */
		ADVANCE(16);
		i_debug("got guid %s", guid_128_to_uuid_string(preq->cred.aaguid, FORMAT_RECORD));
uint16_t cred_size = be16_to_cpu_unaligned(ptr);
		i_debug("cred size = %u, size = %zu", cred_size, size);
		if (cred_size > size) {
			*error_r = t_strdup_printf("too large size (%u)", cred_size);
			return FALSE;
		}
		ADVANCE(2);
		preq->cred.key_id =
			buffer_create_dynamic(preq->auth_request.pool, cred_size);
		buffer_append(preq->cred.key_id, ptr, cred_size);
		i_debug("Got credential id %s", binary_to_hex(ptr, cred_size));
		ADVANCE(cred_size);
		/* CBOR decode rest */
		passkey_decode_public_key(preq, ptr, size);
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
		preq->cd = t_buffer_create(32);
		unsigned char *fillbuf = buffer_get_space_unsafe(preq->cd, 0, 32);
		random_fill(fillbuf, 32);
		buffer_set_used_size(preq->cd, 32);

		/* build a request */
		cbor_item_t *root = cbor_new_definite_map(5);
		passkey_cbor_add_string(root, "rpId", "example.com");
		passkey_cbor_add_buffer(root, "challenge", preq->cd);
		passkey_cbor_add_ulong(root, "timeout", 60000);

		cbor_item_t *allow_credentials = cbor_new_definite_map(2);
		passkey_cbor_add_buffer(allow_credentials, "id", preq->cred.key_id);
		passkey_cbor_add_string(allow_credentials, "type", "public-key");
		cbor_item_t *arrCred = cbor_new_definite_array(1);
		cbor_array_push(arrCred, allow_credentials);
		struct cbor_pair pair;
		pair.key = cbor_build_string("allowCredentials");
		pair.value = arrCred;
		cbor_map_add(root, pair);
		passkey_cbor_add_string(root, "userVerification", "required");
		buffer_t *tmp = t_buffer_create(256);
		fillbuf = buffer_get_space_unsafe(tmp, 0, 256);
		size_t used = cbor_serialize_map(root, fillbuf, 256);
		buffer_set_used_size(tmp, used);

		preq->have_user = TRUE;
		cbor_decref(&root);
		auth_request_handler_reply_continue(req, tmp->data, tmp->used);
	}
}

static bool
mech_passkey_validate(struct passkey_auth_request *preq,
		      const unsigned char *data, size_t len)
{
	/* now we validate the response */
	struct cbor_load_result result;
	cbor_item_t *item = cbor_load(data, len, &result);
	size_t npairs = cbor_map_size(item);
	struct cbor_pair *pairs = cbor_map_handle(item);
	buffer_t *signature = NULL;
	unsigned char digest[SHA256_RESULTLEN];
	buffer_t *authdata = NULL;
	memset(digest, 0, sizeof(digest));

	for (size_t i = 0; i < npairs; i++) {
		struct cbor_pair *pair = pairs + i;
		size_t klen = cbor_string_length(pair->key);
		const char *key = t_strndup(cbor_string_handle(pair->key), klen);
		if (strcmp(key, "signature") == 0) {
			size_t len = cbor_bytestring_length(pair->value);
			signature = t_buffer_create(len);
			buffer_append(signature, cbor_bytestring_handle(pair->value), len);
			i_debug("signature: %zu bytes", len);
		} else if (strcmp(key, "clientDataJSON") == 0) {
			/* hash this */
			size_t len = cbor_bytestring_length(pair->value);
			const void *data = cbor_bytestring_handle(pair->value);
			sha256_get_digest(data, len, digest);
			i_debug("clientDataJSON: %zu bytes", len);
		} else if (strcmp(key, "authenticatorData") == 0) {
			size_t len = cbor_bytestring_length(pair->value);
			authdata = t_buffer_create(len);
			buffer_append(authdata, cbor_bytestring_handle(pair->value), len);
			i_debug("authenticatorData: %zu bytes", len);
		}
	}

	buffer_t *signdata = t_buffer_create(32);
	buffer_append(signdata, authdata->data, authdata->used);
	buffer_append(signdata, digest, sizeof(digest));
	bool valid;
	const char *error;

	if (!dcrypt_verify(preq->cred.pubkey, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
			   signdata->data, signdata->used,
			   signature->data, signature->used, &valid,
		      	   DCRYPT_PADDING_DEFAULT, &error)) {
		i_debug("error: %s", error);
		valid = FALSE;
	}
	return valid;
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
	} else if (!preq->have_user) {
		const char *username = t_strndup(data, data_len);
		if (!auth_request_set_username(req, username, &error)) {
			e_error(req->mech_event, "Invalid username: %s", error);
			auth_request_fail(req);
			return;
		}
		auth_request_lookup_credentials(req, PASSKEY_SCHEME,
						passkey_lookup_credentials_callback);
		return;
	} else {
		/* validate attestation */
		if (mech_passkey_validate(preq, data, data_len)) {
			const char *reply = "{\"token-type\":\"oauth2\",\"token\":\"90db73ca-e1ff-11ef-b547-67deccb6b34f\"}";
			auth_request_success(req, reply, strlen(reply));
			return;
		}
	}
	auth_request_fail(req);
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

static int passkey_password_verify(const char *plaintext,
				   const struct password_generate_params *params,
				   const unsigned char *raw_password, size_t size,
				   const char **error_r)
{
	*error_r = "PASSKEY cannot be verified";
	return -1;
}

static void passkey_password_generate(const char *plaintext,
				      const struct password_generate_params *params,
				      const unsigned char **raw_password_r,
				      size_t *size_r)
{
	*raw_password_r = (const unsigned char*)"*";
	*size_r = 1;
}


static const struct password_scheme scheme_passkey =
{
	.name = "PASSKEY",
	.password_generate = passkey_password_generate,
	.password_verify = passkey_password_verify,
};

void mech_passkey_init(void)
{
	dcrypt_initialize(NULL, NULL, NULL);
	mech_register_module(&mech_passkey_module);
	password_scheme_register(&scheme_passkey);
}

void mech_passkey_deinit(void)
{
	mech_unregister_module(&mech_passkey_module);
	password_scheme_unregister(&scheme_passkey);
	dcrypt_deinitialize();
}
