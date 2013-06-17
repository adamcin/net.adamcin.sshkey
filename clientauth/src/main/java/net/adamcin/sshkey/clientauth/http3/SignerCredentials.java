package net.adamcin.sshkey.clientauth.http3;

import net.adamcin.sshkey.commons.Signer;
import org.apache.commons.httpclient.Credentials;

public final class SignerCredentials implements Credentials {

    private Signer signer;

    public SignerCredentials(Signer signer) {
        this.signer = signer;
    }

    public Signer getSigner() {
        return signer;
    }
}
