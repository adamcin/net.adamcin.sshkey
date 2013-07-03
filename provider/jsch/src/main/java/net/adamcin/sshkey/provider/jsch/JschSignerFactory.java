package net.adamcin.sshkey.provider.jsch;

import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.SignerFactory;

public class JschSignerFactory extends SignerFactory {

    public Signer getInstance() {
        return new JschSigner();
    }
}
