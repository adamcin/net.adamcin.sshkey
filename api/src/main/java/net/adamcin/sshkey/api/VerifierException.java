package net.adamcin.sshkey.api;

public final class VerifierException extends Exception {

    public VerifierException() {
    }

    public VerifierException(String message) {
        super(message);
    }

    public VerifierException(String message, Throwable cause) {
        super(message, cause);
    }

    public VerifierException(Throwable cause) {
        super(cause);
    }
}
