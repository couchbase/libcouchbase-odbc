/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2026 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * JWT Analytics example — connects via TLS and runs SELECT 1 AS result.
 *
 * Setup:
 *   curl -X POST http://localhost:9000/settings/developerPreview \
 *     -u couchbase:couchbase -d 'enabled=true'
 *
 *   curl -X POST http://localhost:9000/settings/security \
 *     -u couchbase:couchbase -d 'oauthBearerEnabled=true'
 *
 *   curl -X PUT http://localhost:9000/settings/jwt \
 *     -H 'Content-Type: application/json' -u couchbase:couchbase \
 *     -d '{"enabled":true,"issuers":[{"name":"https://idp.capdp.com/realms/cb",
 *           "signingAlgorithm":"RS384","audClaim":"azp","audienceHandling":"any",
 *           "audiences":["test-client"],"subClaim":"preferred_username",
 *           "publicKeySource":"jwks_uri",
 *           "jwksUri":"https://idp.capdp.com/realms/cb/protocol/openid-connect/certs",
 *           "jwksUriTlsVerifyPeer":false}]}'
 *
 *   curl -X PUT http://localhost:9000/settings/rbac/users/external/admin \
 *     -H 'Content-Type: application/x-www-form-urlencoded' \
 *     -u couchbase:couchbase \
 *     --data-urlencode "name=external-admin-user" \
 *     --data-urlencode "roles=admin"
 *
 * Run:
 *   curl -s http://localhost:9000/pools/default/certificate \
 *     -u couchbase:couchbase > /tmp/cb-ca.pem
 *
 *   export LCB_CONNSTR="couchbases://localhost:11998?truststorepath=/tmp/cb-ca.pem"
 *   export JWT_TOKEN=$(curl -sk -X POST \
 *     'https://idp.capdp.com/realms/cb/protocol/openid-connect/token' \
 *     -H 'Content-Type: application/x-www-form-urlencoded' \
 *     -d 'grant_type=password&scope=openid&client_id=test-client' \
 *     -d 'client_secret=<secret>&username=admin@localhost.com&password=<password>' \
 *     | jq -r .access_token)
 *
 *   ./bin/examples/analytics_jwt_tls
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <libcouchbase/couchbase.h>

static void fail(const char *msg)
{
    fprintf(stderr, "[\x1b[31mERROR\x1b[0m] %s\n", msg);
    exit(EXIT_FAILURE);
}

static void check(lcb_STATUS err, const char *msg)
{
    if (err != LCB_SUCCESS) {
        char buf[1024] = {0};
        snprintf(buf, sizeof(buf), "%s: %s", msg, lcb_strerror_short(err));
        fail(buf);
    }
}

static void row_callback(lcb_INSTANCE * /*instance*/, int /*type*/, const lcb_RESPANALYTICS *resp)
{
    const char *row;
    size_t nrow;
    lcb_STATUS rc = lcb_respanalytics_status(resp);
    lcb_respanalytics_row(resp, &row, &nrow);

    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "Query error: %s — %.*s\n", lcb_strerror_short(rc), (int)nrow, row);
        return;
    }
    if (lcb_respanalytics_is_final(resp)) {
        fprintf(stdout, "META: %.*s\n", (int)nrow, row);
    } else {
        fprintf(stdout, "ROW:  %.*s\n", (int)nrow, row);
    }
}

int main(void)
{
    const char *connstr   = getenv("LCB_CONNSTR");
    const char *jwt_token = getenv("JWT_TOKEN");

    if (!connstr || !jwt_token || strcmp(jwt_token, "null") == 0 || jwt_token[0] == '\0') {
        fprintf(stderr,
                "Usage:\n"
                "  export LCB_CONNSTR=\"couchbases://localhost:11998?truststorepath=/tmp/cb-ca.pem\"\n"
                "  export JWT_TOKEN=$(curl -sk -X POST \\\n"
                "    'https://idp.capdp.com/realms/cb/protocol/openid-connect/token' \\\n"
                "    -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                "    -d 'grant_type=password&scope=openid&client_id=test-client' \\\n"
                "    -d 'client_secret=<secret>&username=admin@localhost.com&password=<pw>' \\\n"
                "    | jq -r .access_token)\n"
                "  ./analytics_jwt_tls\n"
                "Note: use -sk on the curl for idp.capdp.com (expired TLS cert).\n");
        return EXIT_FAILURE;
    }

    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, jwt_token, strlen(jwt_token));
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "lcbauth_set_jwt: %s\n", lcb_strerror_short(rc));
        lcbauth_unref(auth);
        return EXIT_FAILURE;
    }

    lcb_INSTANCE *instance = nullptr;
    {
        lcb_CREATEOPTS *opts = nullptr;
        lcb_createopts_create(&opts, LCB_TYPE_CLUSTER);
        lcb_createopts_connstr(opts, connstr, strlen(connstr));
        lcb_createopts_authenticator(opts, auth);
        rc = lcb_create(&instance, opts);
        lcb_createopts_destroy(opts);
    }

    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "lcb_create: %s\n", lcb_strerror_short(rc));
        if (rc == LCB_ERR_OPTIONS_CONFLICT) {
            fprintf(stderr, "  Hint: Use 'couchbases://' (TLS) — JWT requires TLS.\n");
        }
        lcbauth_unref(auth);
        return EXIT_FAILURE;
    }

    check(lcb_connect(instance), "schedule connection");
    lcb_wait(instance, LCB_WAIT_DEFAULT);
    rc = lcb_get_bootstrap_status(instance);
    if (rc != LCB_SUCCESS) {
        fprintf(stderr, "bootstrap: %s\n", lcb_strerror_short(rc));
        if (rc == LCB_ERR_AUTHENTICATION_FAILURE) {
            fprintf(stderr,
                    "  Hint: Check that preferred_username in the token matches\n"
                    "  the Couchbase external user id (e.g. 'admin').\n"
                    "  Verify the external user exists:\n"
                    "    curl http://localhost:9000/settings/rbac/users/external -u couchbase:couchbase\n");
        }
        lcbauth_unref(auth);
        lcb_destroy(instance);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Connected via JWT auth — %s\n\n", connstr);

    const char *statement = "SELECT 1 AS result;";
    fprintf(stdout, "Executing: %s\n", statement);

    lcb_CMDANALYTICS *cmd;
    lcb_cmdanalytics_create(&cmd);
    lcb_cmdanalytics_callback(cmd, row_callback);
    lcb_cmdanalytics_statement(cmd, statement, strlen(statement));
    check(lcb_analytics(instance, nullptr, cmd), "schedule analytics query");
    lcb_cmdanalytics_destroy(cmd);
    lcb_wait(instance, LCB_WAIT_DEFAULT);

    lcbauth_unref(auth);
    lcb_destroy(instance);
    return EXIT_SUCCESS;
}
