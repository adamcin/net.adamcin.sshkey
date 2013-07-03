package net.adamcin.sshkey.provider.jsch;

import net.adamcin.sshkey.api.Verifier;
import net.adamcin.sshkey.api.VerifierFactory;

public class JschVerifierFactory extends VerifierFactory {

    public Verifier getInstance() {
        return new JschVerifier();
    }
}
