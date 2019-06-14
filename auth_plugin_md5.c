#include <string.h>
#include <stdio.h>
#include <malloc.h> 
#include <mosquitto.h>
#include <mosquitto_plugin.h>
#include <openssl/md5.h>

int md5_server_user_prefix_size = 0;
char *md5_server_user_prefix;
int md5_client_user_prefix_size = 0;
char *md5_client_user_prefix;
int md5_server_hashseed_size = 0;
char *md5_server_hashseed;
int md5_client_hashseed_size = 0;
char *md5_client_hashseed;
int md5_topic_prefix_size = 0;
char *md5_topic_prefix;
int md5_topic_suffix_size = 0;
char *md5_topic_suffix;

int md5_is_client(const char* username) 
{
	if (username == NULL) {
		return 0;
	}
	if (strncmp(username, md5_client_user_prefix, md5_client_user_prefix_size) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int md5_is_server(const char* username) 
{
	if (username == NULL) {
		return 0;
	}
	if (strncmp(username, md5_server_user_prefix, md5_server_user_prefix_size) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int md5_is_valid_client_topic(const char* username, const char* topic)
{
	if (!md5_is_client(username)) {
		return 0;
	}
	int ulen = strlen(username);
	int tsize = md5_topic_prefix_size + ulen - md5_client_user_prefix_size + md5_topic_suffix_size + 1;
	char *topic_p = malloc(tsize);
	memset(topic_p, 0, tsize);
	strcat(topic_p, md5_topic_prefix);
	strcat(topic_p, username + md5_client_user_prefix_size);
	strcat(topic_p, md5_topic_suffix);
#ifdef MQAP_DEBUG
	fprintf(stderr, "md5_is_valid_client_topic: topic=%s, predefined topic=%s\n", topic, topic_p);
#endif
	if (strncmp(topic, topic_p, tsize - 1) == 0) {
		return 1;
	} else {
		return 0;
	}
}

int mosquitto_auth_plugin_version(void)
{
	return MOSQ_AUTH_PLUGIN_VERSION;
}

// int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
// {

// 	return MOSQ_ERR_SUCCESS;
// }

// int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count)
// {
// 	return MOSQ_ERR_SUCCESS;
// }

// int mosquitto_auth_security_init(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
// {
// 	return MOSQ_ERR_SUCCESS;
// }

// int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_auth_opt *auth_opts, int auth_opt_count, bool reload)
// {
// 	return MOSQ_ERR_SUCCESS;
// }

// int mosquitto_auth_acl_check(void *user_data, const char *clientid, const char *username, const char *topic, int access)
// {

// 	return MOSQ_ERR_SUCCESS;
// }

// int mosquitto_auth_unpwd_check(void *user_data, const char *username, const char *password)
// {

// 	return MOSQ_ERR_SUCCESS;
// }

// int mosquitto_auth_psk_key_get(void *user_data, const char *hint, const char *identity, char *key, int max_key_len)
// {
// 	return MOSQ_ERR_AUTH;
// }

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count){
	return MOSQ_ERR_SUCCESS;
}
int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count){
	return MOSQ_ERR_SUCCESS;
}
int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload){
	return MOSQ_ERR_SUCCESS;
}
int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload){
	return MOSQ_ERR_SUCCESS;
}
int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg){
	return MOSQ_ERR_SUCCESS;
}
int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password){
	return MOSQ_ERR_SUCCESS;
}
int mosquitto_auth_psk_key_get(void *user_data, struct mosquitto *client, const char *hint, const char *identity, char *key, int max_key_len){
	return MOSQ_ERR_AUTH;
}