/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017-2020 Couchbase, Inc.
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

#include <libcouchbase/couchbase.h>
#include "auth-priv.h"
#include "strcodecs/strcodecs.h"
#include "cJSON/cJSON.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace lcb;

/**
 * Decode a single Base64URL component (header or payload) from @p part into
 * a NULL-terminated std::string.  Returns an empty string on error.
 */
static bool decode_jwt_component(const std::string &part, std::string &out)
{
    if (part.empty()) {
        return false;
    }
    /* Maximum decoded length: ceil(n/4)*3 + 1 for the NUL terminator */
    std::size_t max_dec = (part.size() / 4 + 1) * 3 + 1;
    std::vector<char> buf(max_dec, '\0');
    std::ptrdiff_t n = lcb_base64url_decode(part.c_str(), part.size(), buf.data(), max_dec);
    if (n < 0) {
        return false;
    }
    out.assign(buf.data(), static_cast<std::size_t>(n));
    return true;
}

/**
 * Structurally validate @p token and extract the `exp` claim.
 *
 *  1. Split on '.', require exactly 3 parts.
 *  2. Base64URL-decode all three parts; reject any malformed segment.
 *  3. Parse header and payload as JSON objects; reject non-objects.
 *  4. Read the numeric `exp` claim from the payload (0 if absent).
 *
 * The signature (third component) is validated as well-formed Base64URL but
 * is not verified, that is a server-side concern.
 *
 * @param token    The encoded JWT string.
 * @param exp_out  Populated with the `exp` epoch value, or 0 if absent.
 * @return LCB_SUCCESS on success; LCB_ERR_INVALID_ARGUMENT on any error.
 */
static lcb_STATUS parse_jwt(const std::string &token, int64_t &exp_out)
{
    exp_out = 0;

    /* Step 1 */
    std::vector<std::string> parts;
    parts.reserve(4); /* reserve one extra to detect >3 parts cheaply */
    std::string::size_type pos = 0;
    std::string::size_type dot;
    while ((dot = token.find('.', pos)) != std::string::npos) {
        parts.push_back(token.substr(pos, dot - pos));
        pos = dot + 1;
    }
    parts.push_back(token.substr(pos));

    if (parts.size() != 3) {

        return LCB_ERR_INVALID_ARGUMENT;
    }

    /* Step 2 */
    std::string header_json, payload_json, sig_ignored;
    if (!decode_jwt_component(parts[0], header_json) || !decode_jwt_component(parts[1], payload_json) ||
        !decode_jwt_component(parts[2], sig_ignored)) {
        return LCB_ERR_INVALID_ARGUMENT;
    }

    /* Step 3 */
    cJSON *header = cJSON_Parse(header_json.c_str());
    if (header == nullptr || header->type != cJSON_Object) {
        cJSON_Delete(header);
        return LCB_ERR_INVALID_ARGUMENT;
    }
    cJSON_Delete(header);

    cJSON *payload = cJSON_Parse(payload_json.c_str());
    if (payload == nullptr || payload->type != cJSON_Object) {
        cJSON_Delete(payload);
        return LCB_ERR_INVALID_ARGUMENT;
    }

    /* Step 4 */
    cJSON *exp_item = cJSON_GetObjectItem(payload, "exp");
    if (exp_item != nullptr && exp_item->type == cJSON_Number) {
        exp_out = static_cast<int64_t>(exp_item->valuedouble);
    }
    cJSON_Delete(payload);

    return LCB_SUCCESS;
}

/**
 * Build and store all JWT-derived strings from @p token.
 */
static void store_jwt(const std::string &token, int64_t exp,
                      std::string &jwt_out, std::string &bearer_out,
                      std::string &sasl_out, int64_t &exp_out)
{

    lcb::secure_zero_string(jwt_out);
    lcb::secure_zero_string(bearer_out);
    lcb::secure_zero_string(sasl_out);

    jwt_out = token;
    exp_out = exp;

    /* HTTP header value: "Bearer <jwt>" */
    bearer_out = "Bearer ";
    bearer_out += token;

    /* SASL OAUTHBEARER initial-response payload (RFC 7628):
     *   "n,,\x01auth=Bearer <jwt>\x01\x01" */
    sasl_out  = "n,,\x01" "auth=Bearer ";
    sasl_out += token;
    sasl_out += "\x01\x01";
}

lcb_STATUS Authenticator::set_jwt(const std::string &token)
{
    if (!username_.empty() || !password_.empty() || !buckets_.empty()) {
        return LCB_ERR_OPTIONS_CONFLICT;
    }

    int64_t exp;
    lcb_STATUS rc = parse_jwt(token, exp);
    if (rc != LCB_SUCCESS) {
        return rc;
    }

    store_jwt(token, exp, jwt_, jwt_bearer_header_, jwt_sasl_payload_, jwt_exp_seconds_);
    mode_ = LCBAUTH_MODE_JWT;
    return LCB_SUCCESS;
}

lcb_AUTHENTICATOR *lcbauth_new()
{
    return new Authenticator{};
}

lcb_STATUS lcbauth_add_pass(lcb_AUTHENTICATOR *auth, const char *u, const char *p, int flags)
{
    return auth->add(u, p, flags);
}

lcb_STATUS Authenticator::add(const char *u, const char *p, int flags)
{
    if (!u) {
        return LCB_ERR_INVALID_ARGUMENT;
    }

    if (!(flags & (LCBAUTH_F_BUCKET | LCBAUTH_F_CLUSTER))) {
        return LCB_ERR_INVALID_ARGUMENT;
    }

    /* JWT mode uses bearer tokens, not username/password credentials.
     * Mixing them is an error. */
    if (mode_ == LCBAUTH_MODE_JWT) {
        return LCB_ERR_OPTIONS_CONFLICT;
    }

    if (mode_ == LCBAUTH_MODE_RBAC && (flags & LCBAUTH_F_BUCKET)) {
        return LCB_ERR_OPTIONS_CONFLICT;
    }

    if (flags & LCBAUTH_F_CLUSTER) {
        if (p) {
            username_ = u;
            password_ = p;
        } else {
            username_.clear();
            password_.clear();
        }
    }

    if (flags & LCBAUTH_F_BUCKET) {
        if (p) {
            buckets_[u] = p;
        } else {
            buckets_.erase(u);
        }
    }

    return LCB_SUCCESS;
}

lcbauth_CREDENTIALS Authenticator::credentials_for(lcbauth_SERVICE service, lcbauth_REASON reason, const char *host,
                                                   const char *port, const char *bucket) const
{
    lcbauth_CREDENTIALS creds{};
    creds.reason(reason);
    creds.service(service);

    switch (mode_) {
        case LCBAUTH_MODE_RBAC:
            creds.username(username_);
            creds.password(password_);
            break;

        case LCBAUTH_MODE_DYNAMIC:
            if (callback_ == nullptr) {
                creds.result(LCBAUTH_RESULT_NOT_AVAILABLE);
            } else {
                if (host) {
                    creds.hostname(host);
                }
                if (port) {
                    creds.port(port);
                }
                if (bucket) {
                    creds.bucket(bucket);
                }
                creds.cookie(cookie_);
                callback_(&creds);
            }
            break;

        case LCBAUTH_MODE_CLASSIC:
            if (bucket) {
                const auto it = buckets_.find(bucket);
                if (it != buckets_.end()) {
                    creds.username(it->first);
                    creds.password(it->second);
                }
            } else {
                creds.result(LCBAUTH_RESULT_NOT_AVAILABLE);
            }
            break;

        case LCBAUTH_MODE_JWT:
            /* JWT authentication does not use username/password.
             * KV auth is performed via SASL OAUTHBEARER and HTTP auth via Bearer header.
             * Return empty credentials with OK result so that callers that
             * check credentials_for() do not treat the result as an error. */
            break;
    }

    return creds;
}

void lcbauth_ref(lcb_AUTHENTICATOR *auth)
{
    auth->incref();
}

void lcbauth_unref(lcb_AUTHENTICATOR *auth)
{
    auth->decref();
}

lcb_AUTHENTICATOR *lcbauth_clone(const lcb_AUTHENTICATOR *src)
{
    return new Authenticator(*src);
}

lcb_STATUS lcbauth_set_mode(lcb_AUTHENTICATOR *src, lcbauth_MODE mode)
{
    return src->set_mode(mode);
}

lcb_STATUS lcbauth_set_callback(lcb_AUTHENTICATOR *auth, void *cookie, void (*callback)(lcbauth_CREDENTIALS *))
{
    return auth->set_callback(cookie, callback);
}

lcb_STATUS lcbauth_credentials_username(lcbauth_CREDENTIALS *credentials, const char *username, size_t username_len)
{
    credentials->username(std::string(username, username_len));
    return LCB_SUCCESS;
}

lcb_STATUS lcbauth_credentials_password(lcbauth_CREDENTIALS *credentials, const char *password, size_t password_len)
{
    credentials->password(std::string(password, password_len));
    return LCB_SUCCESS;
}

lcb_STATUS lcbauth_credentials_result(lcbauth_CREDENTIALS *credentials, lcbauth_RESULT result)
{
    credentials->result(result);
    return LCB_SUCCESS;
}

LIBCOUCHBASE_API lcbauth_SERVICE lcbauth_credentials_service(const lcbauth_CREDENTIALS *credentials)
{
    return credentials->service();
}

lcbauth_REASON lcbauth_credentials_reason(const lcbauth_CREDENTIALS *credentials)
{
    return credentials->reason();
}

lcb_STATUS lcbauth_credentials_hostname(const lcbauth_CREDENTIALS *credentials, const char **hostname,
                                        size_t *hostname_len)
{
    *hostname = credentials->hostname().c_str();
    *hostname_len = credentials->hostname().size();
    return LCB_SUCCESS;
}

lcb_STATUS lcbauth_credentials_port(const lcbauth_CREDENTIALS *credentials, const char **port, size_t *port_len)
{
    *port = credentials->port().c_str();
    *port_len = credentials->port().size();
    return LCB_SUCCESS;
}

lcb_STATUS lcbauth_credentials_bucket(const lcbauth_CREDENTIALS *credentials, const char **bucket, size_t *bucket_len)
{
    *bucket = credentials->bucket().c_str();
    *bucket_len = credentials->bucket().size();
    return LCB_SUCCESS;
}

lcb_STATUS lcbauth_credentials_cookie(const lcbauth_CREDENTIALS *credentials, void **cookie)
{
    *cookie = credentials->cookie();
    return LCB_SUCCESS;
}

lcb_STATUS lcbauth_set_callbacks(lcb_AUTHENTICATOR *, void *, lcb_AUTHCALLBACK, lcb_AUTHCALLBACK)
{
    return LCB_ERR_UNSUPPORTED_OPERATION;
}

lcb_STATUS lcbauth_set_jwt(lcb_AUTHENTICATOR *auth, const char *jwt, size_t jwt_len)
{
    if (auth == nullptr || jwt == nullptr) {
        return LCB_ERR_INVALID_ARGUMENT;
    }
    return auth->set_jwt(std::string(jwt, jwt_len));
}
