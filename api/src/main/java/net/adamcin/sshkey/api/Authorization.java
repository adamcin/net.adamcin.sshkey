package net.adamcin.sshkey.api;

import java.io.Serializable;

/**
 * Representation of the "Authorization: SSHKey ..." header sent by the client in response to a {@link Challenge}
 */
public final class Authorization implements Serializable {

    private final String token;
    private final String signature;

    public Authorization(final String token, final String signature) {
        this.token = token;
        this.signature = signature;
    }

    public Authorization(String token, byte[] signatureBytes) {
        this.token = token;
        this.signature = Base64.toBase64String(signatureBytes);
    }

    public String getToken() {
        return token;
    }

    public String getSignature() {
        return signature;
    }

    public byte[] getSignatureBytes() {
        return Base64.fromBase64String(this.signature);
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
