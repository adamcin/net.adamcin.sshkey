package net.adamcin.sshkey.clientauth.http4;

import net.adamcin.sshkey.api.Signer;
import org.apache.http.auth.Credentials;

import java.security.Principal;

public class SignerCredentials implements Credentials {

    private final Signer signer;

    public SignerCredentials(Signer signer) {
        this.signer = signer;
    }

    public Signer getSigner() {
        return signer;
    }

    public Principal getUserPrincipal() {
        return null;
    }

    public String getPassword() {
        return null;
    }
}
