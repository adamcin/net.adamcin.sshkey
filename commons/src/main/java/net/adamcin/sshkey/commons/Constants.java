package net.adamcin.sshkey.commons;

public final class Constants {

    public static final String SCHEME = "SSHKey";

    public static final String SCHEME_NAME = "SSH Key Authentication";

    public static final String HEADER_CHALLENGE = "WWW-Authenticate";

    public static final String HEADER_AUTHORIZATION = "Authorization";

    public static final String HEADER_X_SSHKEY_USERNAME = "X-SSHKey-Username";

    public static final String HEADER_X_SSHKEY_FINGERPRINT = "X-SSHKey-Fingerprint";

    public static final String HEADER_X_SSHKEY_REQUEST_LOGIN = "X-SSHKey-RequestLogin";

    private Constants() {
    }
}
