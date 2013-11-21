/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

package net.adamcin.sshkey.api;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Representation of the "WWW-Authenticate: SSHKey ..." authentication challenge header sent by the server.
 */
public final class Challenge implements Serializable {
    private static final String CRLF = "\r\n";
    private static final String RFC2617_PARAM = "=\"([^\"]*)\"";
    private static final Pattern REALM_PATTERN = Pattern.compile(Constants.REALM + RFC2617_PARAM);
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile(Constants.FINGERPRINT + RFC2617_PARAM);
    private static final Pattern NONCE_MATCHER = Pattern.compile(Constants.NONCE + RFC2617_PARAM);

    private final String realm;
    private final String fingerprint;
    private final String nonce;
    private final String host;
    private final String userAgent;

    public Challenge(final String realm,
                     final String fingerprint,
                     final String nonce,
                     final String host,
                     final String userAgent) {
        this.realm = realm;
        this.fingerprint = fingerprint;
        this.nonce = nonce;
        this.host = host != null ? host : "";
        this.userAgent = userAgent != null ? userAgent : "";
    }

    public String getRealm() {
        return realm;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getNonce() {
        return nonce;
    }

    public String getHost() {
        return host;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getHash() {
        return new StringBuilder(host).append(CRLF)
                .append(realm).append(CRLF)
                .append(nonce).append(CRLF)
                .append(userAgent).toString();
    }

    public byte[] getHashBytes() {
        return getHash().getBytes(Constants.CHARSET);
    }

    public String getHeaderValue() {
        return String.format(
                "%s " + Constants.REALM + "=\"%s\", "
                        + Constants.FINGERPRINT + "=\"%s\", "
                        + Constants.NONCE + "=\"%s\"",
                Constants.SCHEME, this.realm, this.fingerprint, this.nonce
        );
    }

    @Override
    public String toString() {
        return getHeaderValue();
    }

    public static Challenge parseChallenge(final String challenge, final String host, final String userAgent) {
        Matcher realmMatcher = REALM_PATTERN.matcher(challenge);
        Matcher fingerprintMatcher = FINGERPRINT_PATTERN.matcher(challenge);
        Matcher nonceMatcher = NONCE_MATCHER.matcher(challenge);

        if (realmMatcher.find() && fingerprintMatcher.find() && nonceMatcher.find()) {
            String realm = realmMatcher.group(1);
            String fingerprint = fingerprintMatcher.group(1);
            String nonce = nonceMatcher.group(1);
            return new Challenge(realm, fingerprint, nonce, host, userAgent);
        }

        return null;
    }
}
