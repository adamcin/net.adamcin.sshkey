package net.adamcin.sshkey.commons;

public final class Authorization {

    private final String sessionId;
    private final String signature;

    public Authorization(String sessionId, String signature) {
        this.sessionId = sessionId;
        this.signature = signature;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return Constants.SCHEME + " " + sessionId + " " + signature;
    }

    public static Authorization parse(String header) {
        if (header == null) {
            return null;
        }

        String[] parts = header.split(" ");

        if (parts.length != 3 && !Constants.SCHEME.equals(parts[0])) {
            return null;
        }

        String sessionId = parts[1];
        String signature = parts[2];

        return new Authorization(sessionId, signature);
    }
}
