package net.adamcin.sshkey.commons;

import java.nio.charset.Charset;

public final class Constants {

    public static final String SCHEME = "SSHKey";

    public static final String HEADER_CHALLENGE = "WWW-Authenticate";

    public static final String HEADER_AUTHORIZATION = "Authorization";

    public static final String HEADER_HOST = "Host";

    public static final String HEADER_USER_AGENT = "User-Agent";

    public static final String HEADER_X_SSHKEY_USERNAME = "X-SSHKey-Username";

    public static final String HEADER_X_SSHKEY_FINGERPRINT = "X-SSHKey-Fingerprint";

    public static final String CHALLENGE_PARAM_FINGERPRINT = "fingerprint";

    public static final String CHALLENGE_PARAM_TOKEN = "token";

    public static final Charset CHARSET = Charset.forName("ISO-8859-1");

    private Constants() {
    }
}
