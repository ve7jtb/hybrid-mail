/* OAuth secrets travel over stdin/stdout, never argv, environment or files. */
#include <libsecret/secret.h>
#include <stdio.h>
#include <string.h>
static const SecretSchema schema = {
    "dev.hybridmail.Credentials", SECRET_SCHEMA_NONE,
    { { "account", SECRET_SCHEMA_ATTRIBUTE_STRING }, { NULL, 0 } }
};
int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[2]) > 128) return 1;
    GError *error = NULL;
    if (!strcmp(argv[1], "get")) {
        char *value = secret_password_lookup_sync(&schema, NULL, &error, "account", argv[2], NULL);
        if (error) { g_error_free(error); return 1; }
        if (!value) return 2;
        size_t n = strlen(value);
        int ok = fwrite(value, 1, n, stdout) == n;
        secret_password_free(value);
        return ok ? 0 : 1;
    }
    if (!strcmp(argv[1], "delete")) {
        secret_password_clear_sync(&schema, NULL, &error, "account", argv[2], NULL);
        if (error) { g_error_free(error); return 1; }
        return 0;
    }
    if (!strcmp(argv[1], "put")) {
        char value[65537];
        size_t n = fread(value, 1, sizeof(value), stdin);
        if (ferror(stdin) || n == 0 || n >= sizeof(value) || memchr(value, 0, n)) return 1;
        value[n] = 0;
        gboolean ok = secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT,
            "PQ Mail Google OAuth credential", value, NULL, &error, "account", argv[2], NULL);
        volatile char *p = value; for (size_t i = 0; i < sizeof(value); i++) p[i] = 0;
        if (error) g_error_free(error);
        return ok ? 0 : 1;
    }
    return 1;
}
