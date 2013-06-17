package net.adamcin.sshkey.commons;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Challenge {
    private static final String CRLF = "\r\n";
    private static final Pattern REALM_PATTERN = Pattern.compile("realm=\"([^\"]*)\"");
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("fingerprint=\"([^\"]*)\"");
    private static final Pattern TOKEN_MATCHER = Pattern.compile("token=\"([^\"\\s]*)\"");

    private final String realm;
    private final String fingerprint;
    private final String token;
    private final String host;
    private final String userAgent;

    public Challenge(String realm, String fingerprint, String token, String host, String userAgent) {
        this.realm = realm;
        this.fingerprint = fingerprint;
        this.token = token;
        this.host = host != null ? host : "";
        this.userAgent = userAgent != null ? userAgent : "";
    }

    public String getRealm() {
        return realm;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getToken() {
        return token;
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
        Matcher sessionIdMatcher = TOKEN_MATCHER.matcher(challenge);

        if (realmMatcher.find() && fingerprintMatcher.find() && sessionIdMatcher.find()) {
            String realm = realmMatcher.group(1);
            String fingerprint = fingerprintMatcher.group(1);
            String sessionId = sessionIdMatcher.group(1);
            return new Challenge(realm, fingerprint, sessionId, host, userAgent);
        }

        return null;
    }

    public byte[] getHash() {
        return new StringBuilder(host).append(CRLF)
                .append(realm).append(CRLF)
                .append(token).append(CRLF)
                .append(userAgent).toString()
                .getBytes(Constants.CHARSET);
    }

    @Override
    public String toString() {
        return String.format("%s realm=\"%s\", fingerprint=\"%s\", token=\"%s\"",
                             Constants.SCHEME, this.realm, this.fingerprint, this.token
        );
    }
}
