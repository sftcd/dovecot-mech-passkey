#define AUTH_REQUEST_FIELDS_CONST

#include "lib.h"
#include "test-common.h"
#include "istream.h"
#include "mech.h"
#include "auth.h"
#include "auth-request.h"
#include "hex-binary.h"
#include "dcrypt.h"

extern void mech_passkey_init(void);

void auth_request_success(struct auth_request *request, const void *data, size_t len)
{
	test_assert(TRUE);
}

void auth_module_load(const char *names)
{
	mech_passkey_init();
}

void auth_request_fail(struct auth_request *request)
{
	i_unreached();
}

void auth_request_internal_failure(struct auth_request *request)
{
	i_unreached();
}

bool auth_request_set_username(struct auth_request *request,
			       const char *username, const char **error_r)
{
	test_assert_strcmp(username, "testuser");
	request->fields.user = i_strdup(username);
	return TRUE;
}

void auth_request_handler_reply_continue(struct auth_request *request,
					 const void *reply, size_t reply_size)
{
	i_debug("R: %s", binary_to_hex(reply, reply_size));
}

void auth_request_continue(struct auth_request *request,
			   const unsigned char *data, size_t data_size)
{
	i_debug("C: %s", binary_to_hex(data, data_size));
	/* send back response */
	/*buffer_t *resp = t_buffer_create(128);
	request->mech->auth_continue(request, resp->data, resp->used);*/
}

void auth_request_lookup_credentials(struct auth_request *request,
				     const char *scheme,
				     lookup_credentials_callback_t *callback)
{
	if (strcmp(request->fields.user, "testuser") == 0) {
		const char *error;
		buffer_t *cred = t_buffer_create(32);
		buffer_append_full_file(cred, "/home/cmouse/projects/mech-passkey/cred", UINT_MAX, &error);
		buffer_delete(cred, 0, 9);
		callback(PASSDB_RESULT_OK, cred->data, cred->used, request);
	} else
		callback(PASSDB_RESULT_USER_UNKNOWN, NULL, 0, request);
}


static void test_mech_passkey(void)
{
	test_begin("mech passkey");
	struct auth_settings set;
	i_zero(&set);
	t_array_init(&set.mechanisms, 1);
	const char *mech_name_passkey = "PASSKEY";
	array_push_back(&set.mechanisms, &mech_name_passkey);

	password_schemes_init();
	mech_register_init(&set);

	struct auth_request req;
	i_zero(&req);
	const struct mech_module *mech = mech_module_find("passkey");
	i_assert(mech != NULL);

	req.mech = mech;
	req.id = 1;
	req.pool = pool_datastack_create();
	req.client_pid = 1;
	req.mech_event = event_create(NULL);
	event_set_forced_debug(req.mech_event, TRUE);
	mech->auth_initial(&req, (const unsigned char*)"testuser", 8);

	event_unref(&req.mech_event);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mech_passkey,
		NULL
	};

	dcrypt_initialize(NULL, NULL, NULL);

	return test_run(test_functions);
}
