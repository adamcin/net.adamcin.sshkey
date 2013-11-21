package net.adamcin.sshkey.api;

import java.util.Set;

/**
 *
 */
public interface IdentityProvider {

    /**
     * Returns true if this repository contains an {@link Identity} with the given fingerprint
     * @param fingerprint
     * @return
     */
    boolean contains(String fingerprint);

    /**
     * @param fingerprint a public key fingerprint
     * @return an {@link Identity} where {@code getFingerprint().equals(fingerprint)} or null if none exists
     */
    Identity get(String fingerprint);

    /**
     * @return a set containing each {@link Identity}'s fingerprint
     */
    Set<String> fingerprints();
}
