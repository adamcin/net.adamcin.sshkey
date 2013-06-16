package net.adamcin.sshkey.commons;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Challenge {
    private static final Pattern REALM_PATTERN = Pattern.compile("realm=\"([^\"]*)\"");
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("fingerprint=\"([^\"]*)\"");
    private static final Pattern SESSIONID_PATTERN = Pattern.compile("sessionId=\"([^\"\\s]*)\"");

    private final String realm;
    private final String fingerprint;
    private final String sessionId;

    public Challenge(String realm, String fingerprint, String sessionId) {
        this.fingerprint = fingerprint;
        this.realm = realm;
        this.sessionId = sessionId;
    }

    public String getRealm() {
        return realm;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getSessionId() {
        return sessionId;
    }

    public static Challenge parseChallenge(final String challenge) {
        Matcher realmMatcher = REALM_PATTERN.matcher(challenge);
        Matcher fingerprintMatcher = FINGERPRINT_PATTERN.matcher(challenge);
        Matcher sessionIdMatcher = SESSIONID_PATTERN.matcher(challenge);

        if (realmMatcher.find() && fingerprintMatcher.find() && sessionIdMatcher.find()) {
            String realm = realmMatcher.group(1);
            String fingerprint = fingerprintMatcher.group(1);
            String sessionId = sessionIdMatcher.group(1);
            return new Challenge(realm, fingerprint, sessionId);
        }

        return null;
    }

    @Override
    public String toString() {
        return String.format("%s realm=\"%s\", fingerprint=\"%s\", sessionId=\"%s\"",
                             Constants.SCHEME, this.realm, this.fingerprint, this.sessionId);
    }
}
