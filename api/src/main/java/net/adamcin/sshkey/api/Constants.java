package net.adamcin.sshkey.api;

import java.nio.charset.Charset;

/**
 * Constant values used by the SSHKey Specification
 */
public final class Constants {

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
     *
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
     * SSHKey login username header
     */
    public static final String SSHKEY_USERNAME = "X-SSHKey-Username";

    /**
     * SSHKey login Public Key fingerprint header
     */
    public static final String SSHKEY_FINGERPRINT = "X-SSHKey-Fingerprint";

    public static final Charset CHARSET = Charset.forName("ISO-8859-1");

    private Constants() {
    }
}
