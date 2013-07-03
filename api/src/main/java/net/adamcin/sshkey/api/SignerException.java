package net.adamcin.sshkey.api;

public final class SignerException extends Exception {

    public SignerException() {
    }

    public SignerException(String message) {
        super(message);
    }

    public SignerException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignerException(Throwable cause) {
        super(cause);
    }
}
