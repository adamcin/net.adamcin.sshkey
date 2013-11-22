package net.adamcin.sshkey.api;

import java.util.Set;

/**
 *
 */
public interface Keychain {

    /**
     * Returns true if this repository contains an {@link Key} with the given fingerprint
     * @param fingerprint
     * @return
     */
    boolean contains(String fingerprint);

    /**
     * @param fingerprint a public key fingerprint
     * @return an {@link Key} where {@code getFingerprint().equals(fingerprint)} or null if none exists
     */
    Key get(String fingerprint);

    /**
     * @return a set containing each {@link Key}'s fingerprint
     */
    Set<String> fingerprints();
}
