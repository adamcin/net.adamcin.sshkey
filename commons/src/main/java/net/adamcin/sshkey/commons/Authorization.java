package net.adamcin.sshkey.commons;

public final class Authorization {

    private final String token;
    private final String signature;

    public Authorization(String token, String signature) {
        this.token = token;
        this.signature = signature;
    }

    public String getToken() {
        return token;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public String toString() {
        return Constants.SCHEME + " " + token + " " + signature;
    }

    public static Authorization parse(String header) {
        if (header == null) {
            return null;
        }

        String[] parts = header.split(" ");

        if (parts.length != 3 && !Constants.SCHEME.equals(parts[0])) {
            return null;
        }

        String token = parts[1];
        String signature = parts[2];

        return new Authorization(token, signature);
    }
}
