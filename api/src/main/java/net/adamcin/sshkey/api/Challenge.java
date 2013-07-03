package net.adamcin.sshkey.api;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Representation of the "WWW-Authenticate: SSHKey ..." authentication challenge header sent by the server.
 */
public final class Challenge implements Serializable {
    private static final String CRLF = "\r\n";
    private static final Pattern REALM_PATTERN = Pattern.compile(Constants.REALM + "=\"([^\"]*)\"");
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile(Constants.FINGERPRINT + "=\"([^\"]*)\"");
    private static final Pattern NONCE_MATCHER = Pattern.compile(Constants.NONCE + "=\"([^\"\\s]*)\"");

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

    public static Challenge parseChallenge(final String challenge, final String host, final String userAgent) {
        Matcher realmMatcher = REALM_PATTERN.matcher(challenge);
        Matcher fingerprintMatcher = FINGERPRINT_PATTERN.matcher(challenge);
        Matcher nonceMatcher = NONCE_MATCHER.matcher(challenge);

        if (realmMatcher.find() && fingerprintMatcher.find() && nonceMatcher.find()) {
            String realm = realmMatcher.group(1);
            String fingerprint = fingerprintMatcher.group(1);
            String sessionId = nonceMatcher.group(1);
            return new Challenge(realm, fingerprint, sessionId, host, userAgent);
        }

        return null;
    }

    public byte[] getHash() {
        return new StringBuilder(host).append(CRLF)
                .append(realm).append(CRLF)
                .append(nonce).append(CRLF)
                .append(userAgent).toString()
                .getBytes(Constants.CHARSET);
    }

    @Override
    public String toString() {
        return String.format("%s " + Constants.REALM + "=\"%s\", "
                                     + Constants.FINGERPRINT + "=\"%s\", "
                                     + Constants.NONCE + "=\"%s\"",
                             Constants.SCHEME, this.realm, this.fingerprint, this.nonce
        );
    }
}
