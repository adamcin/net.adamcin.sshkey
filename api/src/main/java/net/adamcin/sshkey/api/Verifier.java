package net.adamcin.sshkey.api;

import java.io.File;
import java.util.Collection;

public interface Verifier {

    String selectFingerprint(Collection<String> clientFingerprints);

    void readAuthorizedKeys(File authorizedKeysFile) throws VerifierException;

    boolean verify(Challenge challenge, Authorization authorization) throws VerifierException;

    void clear();
}
