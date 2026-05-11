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

#ifndef LCB_AUTH_PRIV_H
#define LCB_AUTH_PRIV_H
#include <libcouchbase/auth.h>

#ifdef __cplusplus
#include <string>
#include <map>
#include <sstream>
#include <cstdint>

struct lcbauth_CREDENTIALS_ {
    void hostname(std::string hostname)
    {
        hostname_ = std::move(hostname);
    }

    void port(std::string port)
    {
        port_ = std::move(port);
    }

    void bucket(std::string bucket)
    {
        bucket_ = std::move(bucket);
    }

    void username(std::string username)
    {
        username_ = std::move(username);
    }

    void password(std::string password)
    {
        password_ = std::move(password);
    }

    void result(lcbauth_RESULT result)
    {
        result_ = result;
    }

    void reason(lcbauth_REASON reason)
    {
        reason_ = reason;
    }

    void cookie(void *cookie)
    {
        cookie_ = cookie;
    }

    void *cookie() const
    {
        return cookie_;
    }

    const std::string &username() const
    {
        return username_;
    }

    const std::string &password() const
    {
        return password_;
    }

    const std::string &hostname() const
    {
        return hostname_;
    }

    const std::string &port() const
    {
        return port_;
    }

    const std::string &bucket() const
    {
        return bucket_;
    }

    lcbauth_RESULT result() const
    {
        return result_;
    }

    lcbauth_REASON reason() const
    {
        return reason_;
    }

    lcbauth_SERVICE service() const
    {
        return service_;
    }

    void service(lcbauth_SERVICE service)
    {
        service_ = service;
    }

  private:
    void *cookie_{nullptr};
    std::string hostname_{};
    std::string port_{};
    std::string bucket_{};
    lcbauth_REASON reason_{LCBAUTH_REASON_NEW_OPERATION};
    lcbauth_SERVICE service_{LCBAUTH_SERVICE_UNSPECIFIED};

    /* output */
    lcbauth_RESULT result_{LCBAUTH_RESULT_OK};
    std::string username_{};
    std::string password_{};
};

namespace lcb
{

inline void secure_zero_string(std::string &s)
{
    if (!s.empty()) {
        volatile char *p = &s[0];
        for (std::size_t i = 0; i < s.size(); ++i) {
            p[i] = '\0';
        }
    }
    s.clear();
}

class Authenticator
{
  public:
    Authenticator() = default;

    Authenticator(const Authenticator &other)
        : buckets_{other.buckets_}, username_{other.username_}, password_{other.password_}, mode_{other.mode_},
          cookie_{other.cookie_}, callback_{other.callback_},
          jwt_{other.jwt_}, jwt_bearer_header_{other.jwt_bearer_header_},
          jwt_sasl_payload_{other.jwt_sasl_payload_}, jwt_exp_seconds_{other.jwt_exp_seconds_}
    {
    }

    ~Authenticator()
    {
        secure_zero_string(jwt_);
        secure_zero_string(jwt_bearer_header_);
        secure_zero_string(jwt_sasl_payload_);
    }

    const std::string &username() const
    {
        return username_;
    }

    const std::string &password() const
    {
        return password_;
    }

    lcbauth_CREDENTIALS credentials_for(lcbauth_SERVICE service, lcbauth_REASON reason, const char *host,
                                        const char *port, const char *bucket) const;

    const std::map<std::string, std::string> &buckets() const
    {
        return buckets_;
    }

    const std::string &jwt_bearer_header() const
    {
        return jwt_bearer_header_;
    }

    const std::string &jwt_sasl_payload() const
    {
        return jwt_sasl_payload_;
    }

   /**
     * Returns a safe JWT summary for logs.
     * Example: "jwt(exp=1234567890)" or "jwt(no-exp)".
     * Does not include the actual token.
     */
    std::string auth_summary() const
    {
        if (mode_ != LCBAUTH_MODE_JWT) {
            return "";
        }
        std::ostringstream oss;
        if (jwt_exp_seconds_ > 0) {
            oss << "jwt(exp=" << jwt_exp_seconds_ << ")";
        } else {
            oss << "jwt(no-exp)";
        }
        return oss.str();
    }

    /**
     * Returns a human-readable representation that is safe to log.
     */
    std::string to_string() const
    {
        if (mode_ == LCBAUTH_MODE_JWT) {
            return "JwtAuthenticator{" + auth_summary() + "}";
        }
        std::ostringstream oss;
        oss << "Authenticator{mode=" << static_cast<int>(mode_) << "}";
        return oss.str();
    }

    /**
     * Validate @p token and store it, building the bearer header and SASL
     * payload. Switches the authenticator into LCBAUTH_MODE_JWT.
     *
     * Fails with LCB_ERR_OPTIONS_CONFLICT if non-JWT credentials already
     * exist, or LCB_ERR_INVALID_ARGUMENT if the token is malformed.
     */
    lcb_STATUS set_jwt(const std::string &token);

    size_t refcount() const
    {
        return refcount_;
    }

    void incref()
    {
        ++refcount_;
    }

    void decref()
    {
        if (!--refcount_) {
            delete this;
        }
    }

    lcb_STATUS set_mode(lcbauth_MODE mode)
    {
        if (mode_ == LCBAUTH_MODE_DYNAMIC && callback_ == nullptr) {
            return LCB_ERR_INVALID_ARGUMENT;
        }
        /* Reject switching INTO JWT mode via set_mode() unless JWT material
         * is already present. */
        if (mode == LCBAUTH_MODE_JWT && mode_ != LCBAUTH_MODE_JWT) {
            if (jwt_.empty()) {
                return LCB_ERR_INVALID_ARGUMENT;
            }
        }
        /* In JWT mode, buckets_, username_, and password_ are empty, so the
        * usual "already has creds" check is skipped. Other modes keep the
        * original guard. */
        if (mode_ != LCBAUTH_MODE_JWT) {
            if (buckets_.size() || username_.size() || password_.size()) {
                return LCB_ERR_INVALID_ARGUMENT;
            }
        }
        /* Switching AWAY from JWT mode: clear all JWT state so that a
         * subsequent lcbauth_add_pass() starts with a clean slate. */
        if (mode_ == LCBAUTH_MODE_JWT && mode != LCBAUTH_MODE_JWT) {
            secure_zero_string(jwt_);
            secure_zero_string(jwt_bearer_header_);
            secure_zero_string(jwt_sasl_payload_);

            jwt_exp_seconds_ = 0;
        }
        mode_ = mode;
        return LCB_SUCCESS;
    }

    lcbauth_MODE mode() const
    {
        return mode_;
    }

    lcb_STATUS add(const char *user, const char *pass, int flags);
    lcb_STATUS add(const std::string &user, const std::string &pass, int flags)
    {
        return add(user.c_str(), pass.c_str(), flags);
    }

    lcb_STATUS set_callback(void *cookie, void (*callback)(lcbauth_CREDENTIALS *))
    {
        cookie_ = cookie;
        callback_ = callback;
        return LCB_SUCCESS;
    }

  private:
    size_t refcount_{1};

    std::map<std::string, std::string> buckets_{};
    std::string username_;
    std::string password_;
    lcbauth_MODE mode_{LCBAUTH_MODE_CLASSIC};
    void *cookie_{nullptr};
    void (*callback_)(lcbauth_CREDENTIALS *){nullptr};

    std::string jwt_{};               /* full token (sensitive info) */
    std::string jwt_bearer_header_{}; /* Authorization header: "Bearer <jwt>" */
    std::string jwt_sasl_payload_{};  /* SASL auth message using the JWT */
    int64_t jwt_exp_seconds_{0};       /* token expiry time in seconds, 0 if not set */
};
} // namespace lcb
#endif
#endif /* LCB_AUTH_H */
