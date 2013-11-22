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

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.Set;

/**
 * Constant values used by the SSHKey Specification
 */
public final class Constants {
    public static final Charset CHARSET_LOGIN_ID = Charset.forName("UTF-8");

    /**
     * Identifier for the SSH Key Authentication scheme
     */
    public static final String SCHEME = "SSHKey";

    /**
     * Http response header representing a server authentication challenge
     * @see <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617: HTTP Authentication: Basic and Digest Access Authentication</a>
     */
    public static final String CHALLENGE = "WWW-Authenticate";

    /**
     * Challenge header "realm" parameter
     */
    public static final String REALM = "realm";

    /**
     * Parameter name for challenge-selected SSH Public Key Fingerprint
     */
    public static final String FINGERPRINT = "fingerprint";

    /**
     * Parameter name for challenge-provided nonce
     */
    public static final String NONCE = "nonce";

    /**
     * Http request header representing client credentials
     * @see <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617: HTTP Authentication: Basic and Digest Access Authentication</a>
     */
    public static final String AUTHORIZATION = "Authorization";

    /**
     * Http Host header
     */
    public static final String HOST = "Host";

    /**
     * Http User-Agent header
     */
    public static final String USER_AGENT = "User-Agent";

    /**
     * SSHKey Login ID header
     */
    public static final String SSHKEY_LOGIN_ID = "X-SSHKey-LoginId";

    /**
     * SSHKey Public Key fingerprint header
     */
    public static final String SSHKEY_FINGERPRINT = "X-SSHKey-Fingerprint";

    public static final Charset CHARSET = Charset.forName("ISO-8859-1");

    /**
     * Checks the provided fingerprint for lexical conformance
     * @param fingerprint a generated public key fingerprint
     * @return true if valid or false if the fingerprint fails nullness, emptiness, or white-space checks
     */
    public static boolean validateFingerprint(final String fingerprint) {
        if (fingerprint == null) {
            return false;
        } else if (fingerprint.isEmpty()) {
            return false;
        } else if (fingerprint.matches("^[^\\s*]\\s+.*$")) {
            return false;
        } else {
            return true;
        }
    }


    /**
     *
     */
    public static final Keychain EMPTY_PROVIDER = new Keychain() {
        public boolean contains(String fingerprint) {
            return false;
        }

        public Key get(String fingerprint) {
            return null;
        }

        public Set<String> fingerprints() {
            return Collections.emptySet();
        }
    };

    private Constants() {
    }

    public static String encodeLoginId(String loginId) {
        return Base64.toBase64String(loginId.getBytes(CHARSET_LOGIN_ID));
    }

    public static String decodeLoginId(String encodedLoginId) {
        return new String(Base64.fromBase64String(encodedLoginId), CHARSET_LOGIN_ID);
    }
}
