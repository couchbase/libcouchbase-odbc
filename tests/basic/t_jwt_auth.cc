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
 * @file t_jwt_auth.cc
 * Unit tests for JWT authentication support (lcbauth_set_jwt, OAUTHBEARER SASL, Bearer header).
 */

#include "config.h"
#include "internal.h"
#include "auth-priv.h"
#include "strcodecs/strcodecs.h"

#include <gtest/gtest.h>
#define LIBCOUCHBASE_INTERNAL 1
#include <libcouchbase/couchbase.h>

#include <string>
#include <cstring>

class JwtAuthTest : public ::testing::Test
{
};

/* Valid JWT: header={alg:RS256}, payload={sub:test-user, exp:9999999999} */
static const char VALID_JWT[] =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ0ZXN0LXVzZXIiLCJleHAiOjk5OTk5OTk5OTl9"
    ".SomeBase64UrlSignature";

static const int64_t VALID_JWT_EXP = INT64_C(9999999999);

/* Minimal JWT: no exp claim */
static const char MINIMAL_JWT[] =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJtaW5pbWFsIn0"
    ".sig";


TEST_F(JwtAuthTest, JwtBase64UrlDecodeStandardAlphabet)
{
    /* "hello" base64url-encoded without padding = "aGVsbG8" */
    const char *encoded = "aGVsbG8";
    char dst[16] = {};
    std::ptrdiff_t n = lcb_base64url_decode(encoded, strlen(encoded), dst, sizeof(dst));
    ASSERT_EQ(5, n);
    EXPECT_EQ(std::string("hello"), std::string(dst, n));
}

TEST_F(JwtAuthTest, JwtBase64UrlDecodeUrlSafeChars)
{
    /* '-' and '_' must be translated to '+' and '/'. {0xFB,0xFF,0xFE} -> "+//+" -> url-safe "-__-" */
    const char *url_safe = "-__-";
    char dst[8] = {};
    std::ptrdiff_t n = lcb_base64url_decode(url_safe, strlen(url_safe), dst, sizeof(dst));
    ASSERT_EQ(3, n);
    EXPECT_EQ(0xFB, (unsigned char)dst[0]);
    EXPECT_EQ(0xFF, (unsigned char)dst[1]);
    EXPECT_EQ(0xFE, (unsigned char)dst[2]);
}

TEST_F(JwtAuthTest, JwtBase64UrlDecodeInvalidChars)
{
    /* '!' is not a valid base64 character */
    const char *bad = "!@#$";
    char dst[8] = {};
    std::ptrdiff_t n = lcb_base64url_decode(bad, strlen(bad), dst, sizeof(dst));
    EXPECT_LT(n, 0);
}

TEST_F(JwtAuthTest, JwtBase64UrlDecodeNoPadding)
{
    /* Decoder must add '=' padding automatically. "TWFu" -> "Man" */
    const char *encoded = "TWFu";
    char dst[8] = {};
    std::ptrdiff_t n = lcb_base64url_decode(encoded, strlen(encoded), dst, sizeof(dst));
    ASSERT_EQ(3, n);
    EXPECT_EQ(std::string("Man"), std::string(dst, n));
}

TEST_F(JwtAuthTest, JwtParseValid)
{
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT));
    EXPECT_EQ(LCB_SUCCESS, rc);
    EXPECT_EQ(LCBAUTH_MODE_JWT, auth->mode());

    /* Verify exp was extracted */
    std::string summary = auth->auth_summary();
    std::string expected_exp = "jwt(exp=" + std::to_string(VALID_JWT_EXP) + ")";
    EXPECT_EQ(expected_exp, summary);

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtParseValidNoExp)
{
    /* JWT without exp claim: summary must say "no-exp" */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, MINIMAL_JWT, strlen(MINIMAL_JWT));
    EXPECT_EQ(LCB_SUCCESS, rc);
    EXPECT_EQ("jwt(no-exp)", auth->auth_summary());
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtParseRejectTwoParts)
{
    /* Must require exactly 3 dot-separated components */
    const char *bad = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, bad, strlen(bad));
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, rc);
    EXPECT_NE(LCBAUTH_MODE_JWT, auth->mode()); /* mode must NOT have changed */
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtParseRejectFourParts)
{
    /* Four components (extra dot) — must fail */
    const char *bad = "header.payload.signature.extra";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, bad, strlen(bad));
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, rc);
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtParseRejectBadBase64)
{
    /* '!@#' is not valid Base64URL */
    const char *bad = "!@#.eyJzdWIiOiJ0ZXN0In0.sig";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, bad, strlen(bad));
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, rc);
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtParseRejectNonJsonHeader)
{
    /* base64url("not-json") = "bm90LWpzb24" — header must be a JSON object */
    const char *bad = "bm90LWpzb24.eyJzdWIiOiJ0ZXN0In0.sig";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, bad, strlen(bad));
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, rc);
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtParseRejectNonJsonPayload)
{
    /* base64url("[1,2,3]") = "WzEsMiwzXQ" — payload must be a JSON object, not array */
    const char *bad = "eyJhbGciOiJSUzI1NiJ9.WzEsMiwzXQ.sig";
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcb_STATUS rc = lcbauth_set_jwt(auth, bad, strlen(bad));
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, rc);
    lcbauth_unref(auth);
}

/* =========================================================================
 * Wire-format
 * ========================================================================= */

TEST_F(JwtAuthTest, JwtBearerHeaderShape)
{
    /* Must return exactly "Bearer <token>" */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::string expected = std::string("Bearer ") + VALID_JWT;
    EXPECT_EQ(expected, auth->jwt_bearer_header());

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtSaslPayloadShape)
{
    /* Must produce byte-exact OAUTHBEARER initial response: "n,,\x01auth=Bearer <token>\x01\x01" */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::string expected;
    expected += "n,,";
    expected += '\x01';
    expected += "auth=Bearer ";
    expected += VALID_JWT;
    expected += '\x01';
    expected += '\x01';

    std::string actual = auth->jwt_sasl_payload();
    ASSERT_EQ(expected.size(), actual.size());
    EXPECT_EQ(expected, actual);

    lcbauth_unref(auth);
}

/* =========================================================================
 * Mode isolation
 * ========================================================================= */

TEST_F(JwtAuthTest, JwtModeBlocksAddPass)
{
    /* JWT mode must reject lcbauth_add_pass() */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    EXPECT_EQ(LCB_ERR_OPTIONS_CONFLICT,
              lcbauth_add_pass(auth, "user", "pass", LCBAUTH_F_CLUSTER));
    EXPECT_EQ(LCB_ERR_OPTIONS_CONFLICT,
              lcbauth_add_pass(auth, "bucket", "pass", LCBAUTH_F_BUCKET));

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtModeExplicitSetModeWithoutJwtRejected)
{
    /* set_mode(JWT) MUST fail when no JWT material is present. */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, lcbauth_set_mode(auth, LCBAUTH_MODE_JWT));
    EXPECT_NE(LCBAUTH_MODE_JWT, auth->mode()); /* must NOT have switched */
    EXPECT_TRUE(auth->jwt_bearer_header().empty());
    EXPECT_TRUE(auth->jwt_sasl_payload().empty());
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtModeSetModeAfterSetJwtIsNoop)
{
    /* Once JWT is installed via set_jwt(), set_mode(JWT) is a no-op (succeeds). */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));
    EXPECT_EQ(LCBAUTH_MODE_JWT, auth->mode());
    /* Calling set_mode(JWT) again should succeed (already in JWT mode with material) */
    EXPECT_EQ(LCB_SUCCESS, lcbauth_set_mode(auth, LCBAUTH_MODE_JWT));
    EXPECT_EQ(LCBAUTH_MODE_JWT, auth->mode());
    EXPECT_FALSE(auth->jwt_bearer_header().empty());
    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtModeRoundTrip)
{
    /* Switch JWT → RBAC: JWT state must be cleared */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));
    EXPECT_EQ(LCBAUTH_MODE_JWT, auth->mode());

    /* Switch to RBAC — should succeed because username_/password_ are empty */
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_mode(auth, LCBAUTH_MODE_RBAC));
    EXPECT_EQ(LCBAUTH_MODE_RBAC, auth->mode());

    /* JWT-derived strings must be cleared */
    EXPECT_TRUE(auth->jwt_bearer_header().empty());
    EXPECT_TRUE(auth->jwt_sasl_payload().empty());
    EXPECT_EQ("", auth->auth_summary()); /* summary is empty for non-JWT mode */

    /* Should now be able to add RBAC credentials */
    EXPECT_EQ(LCB_SUCCESS, lcbauth_add_pass(auth, "user", "pass", LCBAUTH_F_CLUSTER));

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtModeConflictWithExistingCreds)
{
    /* set_jwt() must fail if non-JWT credentials already exist */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    lcbauth_set_mode(auth, LCBAUTH_MODE_RBAC);
    lcbauth_add_pass(auth, "user", "pass", LCBAUTH_F_CLUSTER);

    lcb_STATUS rc = lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT));
    EXPECT_EQ(LCB_ERR_OPTIONS_CONFLICT, rc);
    EXPECT_NE(LCBAUTH_MODE_JWT, auth->mode());

    lcbauth_unref(auth);
}

/* =========================================================================
 * Log redaction
 * ========================================================================= */

TEST_F(JwtAuthTest, JwtRedactionToString)
{
    /* to_string() must not contain the raw token, bearer value, or SASL payload */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::string s = auth->to_string();

    /* Must not contain the raw token at all */
    EXPECT_EQ(std::string::npos, s.find(VALID_JWT))
        << "Raw JWT must not appear in to_string(): " << s;

    /* Must not contain "Bearer" (would reveal the header value) */
    EXPECT_EQ(std::string::npos, s.find("Bearer"))
        << "Bearer token must not appear in to_string(): " << s;

    /* Must not contain the SASL payload prefix */
    EXPECT_EQ(std::string::npos, s.find("auth=Bearer"))
        << "SASL payload must not appear in to_string(): " << s;

    EXPECT_NE(std::string::npos, s.find("Jwt")) << "to_string() should identify the JWT mode: " << s;

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, JwtRedactionAuthSummary)
{
    /* auth_summary() may only expose the exp value, not the token */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::string summary = auth->auth_summary();

    EXPECT_EQ(std::string::npos, summary.find(VALID_JWT))
        << "Raw JWT must not appear in auth_summary(): " << summary;

    /* Summary must start with "jwt(" */
    EXPECT_EQ(0U, summary.find("jwt("))
        << "auth_summary() should be in the form jwt(...): " << summary;

    lcbauth_unref(auth);
}

/* =========================================================================
 * Clone
 * ========================================================================= */

TEST_F(JwtAuthTest, JwtClone)
{
    /* lcbauth_clone() must preserve JWT state; clone and original are independent */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    lcb_AUTHENTICATOR *clone = lcbauth_clone(auth);
    ASSERT_NE(nullptr, clone);

    EXPECT_EQ(LCBAUTH_MODE_JWT, clone->mode());
    EXPECT_EQ(auth->jwt_bearer_header(), clone->jwt_bearer_header());
    EXPECT_EQ(auth->jwt_sasl_payload(), clone->jwt_sasl_payload());
    EXPECT_EQ(auth->auth_summary(), clone->auth_summary());

    /* Independent — unref both */
    lcbauth_unref(clone);
    lcbauth_unref(auth);
}

/* =========================================================================
 * Null input guard
 * ========================================================================= */

TEST_F(JwtAuthTest, JwtSetJwtNullPointer)
{
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    EXPECT_EQ(LCB_ERR_INVALID_ARGUMENT, lcbauth_set_jwt(auth, nullptr, 0));
    lcbauth_unref(auth);
}

/* =========================================================================
 * Phase 2: credentials_for() contracts for HTTP
 * ========================================================================= */

TEST_F(JwtAuthTest, Phase2_CredentialsForJwtModeAllServicesEmpty)
{
    /* In JWT mode, credentials_for() must return OK with empty user/pass for all services */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    static const lcbauth_SERVICE services[] = {
        LCBAUTH_SERVICE_KEY_VALUE,
        LCBAUTH_SERVICE_QUERY,
        LCBAUTH_SERVICE_SEARCH,
        LCBAUTH_SERVICE_ANALYTICS,
        LCBAUTH_SERVICE_MANAGEMENT,
        LCBAUTH_SERVICE_EVENTING,
        LCBAUTH_SERVICE_VIEWS,
    };

    for (auto svc : services) {
        auto creds = auth->credentials_for(svc, LCBAUTH_REASON_NEW_OPERATION,
                                           "host", "8093", "bucket");
        EXPECT_EQ(LCBAUTH_RESULT_OK, creds.result())
            << "Expected RESULT_OK for service " << static_cast<int>(svc);
        EXPECT_TRUE(creds.username().empty())
            << "Username must be empty for JWT mode, service " << static_cast<int>(svc);
        EXPECT_TRUE(creds.password().empty())
            << "Password must be empty for JWT mode, service " << static_cast<int>(svc);
    }

    lcbauth_unref(auth);
}

/* =========================================================================
 * Phase 3: SASL OAUTHBEARER payload contracts
 * ========================================================================= */

TEST_F(JwtAuthTest, Phase3_SaslPayloadPrefixAndSuffix)
{
    /* Must match RFC 7628 §3.1: "n,,\x01auth=Bearer <token>\x01\x01" */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::string payload = auth->jwt_sasl_payload();

    /* Must start with "n,," */
    ASSERT_GE(payload.size(), 3U);
    EXPECT_EQ('n',    payload[0]);
    EXPECT_EQ(',',    payload[1]);
    EXPECT_EQ(',',    payload[2]);

    /* Followed by SOH + "auth=Bearer " */
    ASSERT_GE(payload.size(), 16U);
    EXPECT_EQ('\x01', payload[3]);
    EXPECT_EQ(0, payload.compare(4, 12, "auth=Bearer "));

    std::size_t token_start = 16; /* 3 + 1 + 12 */
    ASSERT_GE(payload.size(), token_start + strlen(VALID_JWT) + 2);
    EXPECT_EQ(0, payload.compare(token_start, strlen(VALID_JWT), VALID_JWT));

    /* Ends with SOH SOH */
    EXPECT_EQ('\x01', payload[payload.size() - 2]);
    EXPECT_EQ('\x01', payload[payload.size() - 1]);

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, Phase3_SaslPayloadLength)
{
    /* Total length: len("n,,\x01auth=Bearer ") + len(token) + len("\x01\x01") = 16 + token + 2 */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::size_t expected = 3 + 1 + 12 + strlen(VALID_JWT) + 2; /* "n,," + SOH + "auth=Bearer " + token + SOH SOH */
    EXPECT_EQ(expected, auth->jwt_sasl_payload().size());

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, Phase3_SaslPayloadNotLoggedInSummary)
{
    /* auth_summary() must not expose the SASL payload or raw token */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    std::string summary = auth->auth_summary();

    /* Must not contain any part of the SASL payload */
    EXPECT_EQ(std::string::npos, summary.find("auth=Bearer"));
    EXPECT_EQ(std::string::npos, summary.find(VALID_JWT));
    EXPECT_EQ(std::string::npos, summary.find("n,,"));

    lcbauth_unref(auth);
}

TEST_F(JwtAuthTest, Phase2_RbacCredentialsForAfterJwtRoundTrip)
{
    /* After JWT → RBAC switch, credentials_for() must return RBAC creds again */
    lcb_AUTHENTICATOR *auth = lcbauth_new();
    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_jwt(auth, VALID_JWT, strlen(VALID_JWT)));

    ASSERT_EQ(LCB_SUCCESS, lcbauth_set_mode(auth, LCBAUTH_MODE_RBAC));
    ASSERT_EQ(LCB_SUCCESS, lcbauth_add_pass(auth, "alice", "secret", LCBAUTH_F_CLUSTER));

    auto creds = auth->credentials_for(LCBAUTH_SERVICE_QUERY, LCBAUTH_REASON_NEW_OPERATION,
                                       nullptr, nullptr, "bucket");
    EXPECT_EQ("alice", creds.username());
    EXPECT_EQ("secret", creds.password());
    EXPECT_EQ(LCBAUTH_RESULT_OK, creds.result());

    /* Bearer header must be cleared */
    EXPECT_TRUE(auth->jwt_bearer_header().empty());

    lcbauth_unref(auth);
}
