package net.adamcin.sshkey.clientauth.http3;

import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.auth.AuthScheme;
import org.apache.commons.httpclient.auth.CredentialsNotAvailableException;
import org.apache.commons.httpclient.auth.CredentialsProvider;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 6/15/13
 * Time: 8:29 PM
 * To change this template use File | Settings | File Templates.
 */
public final class SignerCredentialsProvider implements CredentialsProvider {

    private final Signer signer;
    private final CredentialsProvider delegatee;

    public SignerCredentialsProvider(Signer signer, CredentialsProvider delegatee) {
        this.signer = signer;
        this.delegatee = delegatee;
    }

    public CredentialsProvider getDelegatee() {
        return delegatee;
    }

    public Credentials getCredentials(AuthScheme scheme, String host, int port, boolean proxy)
            throws CredentialsNotAvailableException {

        if (Constants.SCHEME.equals(scheme.getSchemeName())) {
            if (signer == null) {
                throw new CredentialsNotAvailableException("SSHKey Signer not available");
            } else {
                return new SignerCredentials(signer);
            }
        } else {
            if (this.delegatee != null) {
                return this.delegatee.getCredentials(scheme, host, port, proxy);
            }
        }
        return null;
    }
}
