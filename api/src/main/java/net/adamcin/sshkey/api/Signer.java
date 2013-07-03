package net.adamcin.sshkey.api;

import java.util.Set;

/**
 * Instance of a Signer, used by an HTTP client to sign a {@link Challenge} and create an {@link Authorization}
 */
public interface Signer {

    Set<String> getFingerprints();

    void addLocalKey(String path, String passPhrase) throws SignerException;

    void addLocalKey(String name, byte[] keyBlob, byte[] passPhrase) throws SignerException;

    Authorization sign(Challenge challenge) throws SignerException;

    void clear() throws SignerException;
}
