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

#include "config.h"
#include "iotests.h"
#include <libcouchbase/couchbase.h>
#include <libcouchbase/utils.h> /* lcb_get_node, LCB_NODE_* */

#ifndef LCB_NO_SSL

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#include "strcodecs/strcodecs.h"

/*
 * The analytics query path over a JWT is the whole of what the ODBC driver and
 * the Power BI connector use, and CouchbaseMock cannot stand in for it: the
 * token is verified by the server. These tests therefore need a real node with
 * a JWT issuer already configured, which tools/jenkins/oi-server-tests sets up.
 * They sign their own tokens with the issuer's shared secret so the expired and
 * forged cases can be covered too.
 */

namespace
{

struct JwtEnv {
    std::string host;
    std::string issuer;
    std::string audience;
    std::string secret;
    std::string groups;
    std::string cacert;

    bool complete() const
    {
        return !host.empty() && !issuer.empty() && !audience.empty() && !secret.empty() && !cacert.empty();
    }
};

JwtEnv readJwtEnv()
{
    JwtEnv env;
    const char *v;
    if ((v = getenv("LCB_TEST_JWT_HOST")) != nullptr) {
        env.host = v;
    }
    if ((v = getenv("LCB_TEST_JWT_ISSUER")) != nullptr) {
        env.issuer = v;
    }
    if ((v = getenv("LCB_TEST_JWT_AUDIENCE")) != nullptr) {
        env.audience = v;
    }
    if ((v = getenv("LCB_TEST_JWT_SECRET")) != nullptr) {
        env.secret = v;
    }
    if ((v = getenv("LCB_TEST_JWT_GROUPS")) != nullptr) {
        env.groups = v;
    }
    if ((v = getenv("LCB_TEST_CLUSTER_CACERT")) != nullptr) {
        env.cacert = v;
    }
    return env;
}

std::string base64url(const std::string &in)
{
    std::vector<char> buf((in.size() / 3 + 1) * 4 + 1);
    int rc = lcb_base64_encode(in.c_str(), in.size(), buf.data(), buf.size());
    EXPECT_EQ(0, rc);
    std::string out(buf.data());
    std::string url;
    url.reserve(out.size());
    for (char c : out) {
        /* RFC 7515 base64url: the alphabet differs and the padding is dropped. */
        if (c == '+') {
            url += '-';
        } else if (c == '/') {
            url += '_';
        } else if (c != '=') {
            url += c;
        }
    }
    return url;
}

std::string jsonEscape(const std::string &s)
{
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
        }
        out += c;
    }
    return out;
}

/**
 * Sign an HS256 token. @p secret is what the issuer was configured with; pass a
 * different one to forge a signature the server must reject.
 */
std::string mintToken(const JwtEnv &env, long expiresInSeconds, const std::string &secret)
{
    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    std::string claims = "{\"iss\":\"" + jsonEscape(env.issuer) + "\",\"sub\":\"lcb-odbc-tests\",\"aud\":\"" +
                         jsonEscape(env.audience) + "\",\"exp\":" + std::to_string(time(nullptr) + expiresInSeconds);
    if (!env.groups.empty()) {
        claims += ",\"groups\":[";
        size_t start = 0;
        bool first = true;
        while (start <= env.groups.size()) {
            size_t comma = env.groups.find(',', start);
            std::string one = env.groups.substr(start, comma == std::string::npos ? std::string::npos
                                                                                  : comma - start);
            if (!one.empty()) {
                if (!first) {
                    claims += ",";
                }
                claims += "\"" + jsonEscape(one) + "\"";
                first = false;
            }
            if (comma == std::string::npos) {
                break;
            }
            start = comma + 1;
        }
        claims += "]";
    }
    claims += "}";

    std::string signing = base64url(header) + "." + base64url(claims);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen = 0;
    HMAC(EVP_sha256(), secret.c_str(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char *>(signing.c_str()), signing.size(), mac, &maclen);
    return signing + "." + base64url(std::string(reinterpret_cast<char *>(mac), maclen));
}

struct AnalyticsResult {
    std::vector<std::string> rows;
    std::string meta;
    lcb_STATUS rc{LCB_SUCCESS};
    bool final{false};
    std::string firstErrorMessage;
    uint32_t firstErrorCode{0};
};

} // namespace

extern "C" {
static void analyticsCallback(lcb_INSTANCE *, int, const lcb_RESPANALYTICS *resp)
{
    AnalyticsResult *res = nullptr;
    lcb_respanalytics_cookie(resp, reinterpret_cast<void **>(&res));

    if (lcb_respanalytics_is_final(resp) != 0) {
        res->final = true;
        res->rc = lcb_respanalytics_status(resp);
        const char *row = nullptr;
        size_t nrow = 0;
        lcb_respanalytics_row(resp, &row, &nrow);
        if (row != nullptr && nrow != 0) {
            res->meta.assign(row, nrow);
        }
        /* The server's own diagnostic lives in the error context; the status
         * code alone is too coarse to assert on. */
        const lcb_ANALYTICS_ERROR_CONTEXT *ctx = nullptr;
        if (lcb_respanalytics_error_context(resp, &ctx) == LCB_SUCCESS && ctx != nullptr) {
            const char *msg = nullptr;
            size_t nmsg = 0;
            lcb_errctx_analytics_first_error_message(ctx, &msg, &nmsg);
            if (msg != nullptr && nmsg != 0) {
                res->firstErrorMessage.assign(msg, nmsg);
            }
            lcb_errctx_analytics_first_error_code(ctx, &res->firstErrorCode);
        }
        return;
    }

    const char *row = nullptr;
    size_t nrow = 0;
    lcb_respanalytics_row(resp, &row, &nrow);
    if (row != nullptr && nrow != 0) {
        res->rows.emplace_back(row, nrow);
    }
}
}

class JwtAnalyticsUnitTest : public MockUnitTest
{
  protected:
    JwtEnv env;

    void SetUp() override
    {
        MockUnitTest::SetUp();
        env = readJwtEnv();
    }

    /**
     * Connection string for the analytics service over TLS. JWT without TLS is
     * refused outright by lcb_create(), so there is no plaintext variant.
     *
     * With @p explicitPort the management endpoint is named the way the ODBC
     * driver's documentation spells it, "<host>:18091=http". That is a
     * different path through connspec: the port carries its type explicitly,
     * where a bare host leaves both to the scheme. The "=http" is not optional
     * once a port is given -- connspec reads a port with no type as the
     * scheme's implicit one, so "couchbases://host:18091" would register a KV
     * TLS endpoint and leave the HTTP bootstrap list empty.
     */
    std::string connstr(bool explicitPort = false) const
    {
        std::string host = env.host + (explicitPort ? ":18091=http" : "");
        return "couchbases://" + host + "?truststorepath=" + env.cacert + "&bootstrap_on=http";
    }

    /** Connect with @p token and return the bootstrap status. */
    lcb_STATUS connectWithToken(const std::string &token, lcb_INSTANCE **out, bool explicitPort = false) const
    {
        lcb_AUTHENTICATOR *auth = lcbauth_new();
        lcb_STATUS rc = lcbauth_set_jwt(auth, token.c_str(), token.size());
        if (rc != LCB_SUCCESS) {
            lcbauth_unref(auth);
            return rc;
        }

        lcb_CREATEOPTS *opts = nullptr;
        std::string cs = connstr(explicitPort);
        lcb_createopts_create(&opts, LCB_TYPE_CLUSTER);
        lcb_createopts_connstr(opts, cs.c_str(), cs.size());
        lcb_createopts_authenticator(opts, auth);

        lcb_INSTANCE *instance = nullptr;
        rc = lcb_create(&instance, opts);
        lcb_createopts_destroy(opts);
        lcbauth_unref(auth);
        if (rc != LCB_SUCCESS) {
            return rc;
        }

        rc = lcb_connect(instance);
        if (rc != LCB_SUCCESS) {
            lcb_destroy(instance);
            return rc;
        }
        lcb_wait(instance, LCB_WAIT_NOCHECK);
        rc = lcb_get_bootstrap_status(instance);
        if (rc != LCB_SUCCESS) {
            lcb_destroy(instance);
            return rc;
        }
        *out = instance;
        return LCB_SUCCESS;
    }

    static lcb_STATUS runQuery(lcb_INSTANCE *instance, const std::string &statement, AnalyticsResult &res)
    {
        lcb_CMDANALYTICS *cmd = nullptr;
        lcb_cmdanalytics_create(&cmd);
        lcb_cmdanalytics_statement(cmd, statement.c_str(), statement.size());
        lcb_cmdanalytics_callback(cmd, analyticsCallback);
        lcb_STATUS rc = lcb_analytics(instance, &res, cmd);
        lcb_cmdanalytics_destroy(cmd);
        if (rc != LCB_SUCCESS) {
            return rc;
        }
        lcb_wait(instance, LCB_WAIT_DEFAULT);
        return LCB_SUCCESS;
    }

    /**
     * Assert the cluster map came from the server over HTTP, which is the only
     * transport the ODBC driver can use: a bucketless JWT connection has no KV
     * credentials to bootstrap over CCCP with. LCB_CNTL_CONFIG_TRANSPORT reads
     * the origin of the config actually in force and answers
     * LCB_ERR_NO_CONFIGURATION for anything synthesized locally, so it tells a
     * served map apart from the static CLCONFIG_CLADMIN fallback -- which
     * lcb_get_bootstrap_status() does not.
     */
    static void assertHttpBootstrap(lcb_INSTANCE *instance)
    {
        lcb_BOOTSTRAP_TRANSPORT tx = LCB_CONFIG_TRANSPORT_LIST_END;
        ASSERT_STATUS_EQ(LCB_SUCCESS, lcb_cntl(instance, LCB_CNTL_GET, LCB_CNTL_CONFIG_TRANSPORT, &tx));
        ASSERT_EQ(LCB_CONFIG_TRANSPORT_HTTP, tx);
        /* The streaming connection the map arrived on is still open. */
        ASSERT_NE(nullptr, lcb_get_node(instance, LCB_NODE_HTCONFIG_CONNECTED, 0));
        ASSERT_GT(lcb_get_num_nodes(instance), 0);
    }
};

#define SKIP_UNLESS_JWT_CONFIGURED()                                                                                   \
    if (!MockEnvironment::getInstance()->isRealCluster()) {                                                            \
        MockEnvironment::printSkipMessage(__FILE__, __LINE__, "need real cluster");                                    \
        return;                                                                                                        \
    }                                                                                                                  \
    if (!env.complete()) {                                                                                             \
        MockEnvironment::printSkipMessage(__FILE__, __LINE__,                                                          \
                                          "need LCB_TEST_JWT_* and LCB_TEST_CLUSTER_CACERT (see "                      \
                                          "tools/jenkins/oi-server-tests)");                                           \
        return;                                                                                                        \
    }

/**
 * The connection string asks for bootstrap_on=http; prove the server answered
 * it. Without this the suite passes on a locally synthesized config and never
 * touches /pools/default/nodeServicesStreaming at all.
 */
TEST_F(JwtAnalyticsUnitTest, testHttpBootstrapWithJwt)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    lcb_INSTANCE *instance = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, connectWithToken(mintToken(env, 600, env.secret), &instance));
    assertHttpBootstrap(instance);

    /* And on the TLS management port, not the plaintext one. 18091 is the
     * default couchbases:// picks when the connection string names no port. */
    const char *cfghost = lcb_get_node(instance, LCB_NODE_HTCONFIG_CONNECTED, 0);
    ASSERT_NE(nullptr, cfghost);
    EXPECT_NE(std::string::npos, std::string(cfghost).find(":18091"));

    lcb_destroy(instance);
}

/**
 * The same, written the way the driver's documentation spells it:
 * "<host>:18091=http". The case above leaves connspec to take the port and its
 * type from the scheme, so the explicit form -- the one a user following the
 * docs will have in their connection string -- goes through a different branch
 * of the parser and is worth covering on its own.
 */
TEST_F(JwtAnalyticsUnitTest, testHttpBootstrapWithExplicitPort)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    lcb_INSTANCE *instance = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, connectWithToken(mintToken(env, 600, env.secret), &instance, true));
    assertHttpBootstrap(instance);

    const char *cfghost = lcb_get_node(instance, LCB_NODE_HTCONFIG_CONNECTED, 0);
    ASSERT_NE(nullptr, cfghost);
    EXPECT_NE(std::string::npos, std::string(cfghost).find(":18091"));

    /* And the connection it produced is usable, not merely established. */
    AnalyticsResult res;
    ASSERT_STATUS_EQ(LCB_SUCCESS, runQuery(instance, "SELECT 1 AS test_result", res));
    EXPECT_TRUE(res.final);
    EXPECT_STATUS_EQ(LCB_SUCCESS, res.rc) << res.firstErrorMessage;

    lcb_destroy(instance);
}

/**
 * The path the ODBC driver takes: a JWT authenticator on an LCB_TYPE_CLUSTER
 * instance, TLS, then an analytics statement.
 */
TEST_F(JwtAnalyticsUnitTest, testQueryWithJwt)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    lcb_INSTANCE *instance = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, connectWithToken(mintToken(env, 600, env.secret), &instance));
    assertHttpBootstrap(instance);

    AnalyticsResult res;
    ASSERT_STATUS_EQ(LCB_SUCCESS, runQuery(instance, "SELECT 1 AS test_result", res));
    EXPECT_TRUE(res.final);
    EXPECT_STATUS_EQ(LCB_SUCCESS, res.rc) << res.firstErrorMessage;
    ASSERT_EQ(1U, res.rows.size());
    EXPECT_NE(std::string::npos, res.rows[0].find("test_result"));

    lcb_destroy(instance);
}

/** Rows stream one callback at a time, so more than one has to arrive. */
TEST_F(JwtAnalyticsUnitTest, testMultipleRowsWithJwt)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    lcb_INSTANCE *instance = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, connectWithToken(mintToken(env, 600, env.secret), &instance));

    AnalyticsResult res;
    ASSERT_STATUS_EQ(LCB_SUCCESS, runQuery(instance, "SELECT RAW i FROM range(1, 5) AS i", res));
    EXPECT_TRUE(res.final);
    EXPECT_STATUS_EQ(LCB_SUCCESS, res.rc) << res.firstErrorMessage;
    EXPECT_EQ(5U, res.rows.size());

    lcb_destroy(instance);
}

/**
 * The payload form, which is what the driver really uses -- it builds the
 * request JSON itself rather than going through the statement setters.
 */
TEST_F(JwtAnalyticsUnitTest, testEncodedPayloadWithJwt)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    lcb_INSTANCE *instance = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, connectWithToken(mintToken(env, 600, env.secret), &instance));

    std::string payload = R"({"statement":"SELECT 1 AS test_result"})";
    lcb_CMDANALYTICS *cmd = nullptr;
    lcb_cmdanalytics_create(&cmd);
    lcb_cmdanalytics_payload(cmd, payload.c_str(), payload.size());
    lcb_cmdanalytics_callback(cmd, analyticsCallback);
    AnalyticsResult res;
    lcb_STATUS rc = lcb_analytics(instance, &res, cmd);
    lcb_cmdanalytics_destroy(cmd);
    ASSERT_STATUS_EQ(LCB_SUCCESS, rc);
    lcb_wait(instance, LCB_WAIT_DEFAULT);

    EXPECT_TRUE(res.final);
    EXPECT_STATUS_EQ(LCB_SUCCESS, res.rc) << res.firstErrorMessage;
    EXPECT_EQ(1U, res.rows.size());

    lcb_destroy(instance);
}

/** A statement the server rejects still has to deliver its diagnostic. */
TEST_F(JwtAnalyticsUnitTest, testCompilationErrorWithJwt)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    lcb_INSTANCE *instance = nullptr;
    ASSERT_STATUS_EQ(LCB_SUCCESS, connectWithToken(mintToken(env, 600, env.secret), &instance));

    AnalyticsResult res;
    ASSERT_STATUS_EQ(LCB_SUCCESS, runQuery(instance, "SELECT * FROM no_such_dataverse.no_such_dataset", res));
    EXPECT_TRUE(res.final);
    EXPECT_NE(LCB_SUCCESS, res.rc);
    EXPECT_FALSE(res.firstErrorMessage.empty());
    EXPECT_NE(0U, res.firstErrorCode);

    lcb_destroy(instance);
}

/** An expired token must not get a session. */
TEST_F(JwtAnalyticsUnitTest, testExpiredTokenRejected)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    /* The issuer's expiryLeewayS defaults to 15s, so back-date well past it. */
    lcb_INSTANCE *instance = nullptr;
    lcb_STATUS rc = connectWithToken(mintToken(env, -3600, env.secret), &instance);
    EXPECT_NE(LCB_SUCCESS, rc) << "expired token was accepted";
    if (rc == LCB_SUCCESS) {
        lcb_destroy(instance);
    }
}

/** So must a token signed with the wrong key. */
TEST_F(JwtAnalyticsUnitTest, testForgedSignatureRejected)
{
    SKIP_UNLESS_JWT_CONFIGURED();

    std::string wrong(env.secret.size(), 'x');
    lcb_INSTANCE *instance = nullptr;
    lcb_STATUS rc = connectWithToken(mintToken(env, 600, wrong), &instance);
    EXPECT_NE(LCB_SUCCESS, rc) << "forged signature was accepted";
    if (rc == LCB_SUCCESS) {
        lcb_destroy(instance);
    }
}

/**
 * TLS is mandatory for JWT: lcb_create() refuses a plaintext connection string
 * before any I/O happens. Needs no server, so it runs against the mock too.
 */
TEST_F(JwtAnalyticsUnitTest, testPlaintextRefused)
{
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    /* Shape only -- the signature is never checked client side. */
    std::string token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln";
    ASSERT_STATUS_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, token.c_str(), token.size()));

    lcb_CREATEOPTS *opts = nullptr;
    std::string cs = "couchbase://localhost";
    lcb_createopts_create(&opts, LCB_TYPE_CLUSTER);
    lcb_createopts_connstr(opts, cs.c_str(), cs.size());
    lcb_createopts_authenticator(opts, auth);

    lcb_INSTANCE *instance = nullptr;
    lcb_STATUS rc = lcb_create(&instance, opts);
    lcb_createopts_destroy(opts);
    lcbauth_unref(auth);

    EXPECT_STATUS_EQ(LCB_ERR_OPTIONS_CONFLICT, rc);
    if (rc == LCB_SUCCESS) {
        lcb_destroy(instance);
    }
}

#endif /* LCB_NO_SSL */
