package net.adamcin.sshkey.clientauth.http4;

import net.adamcin.sshkey.api.Authorization;
import net.adamcin.sshkey.api.Challenge;
import net.adamcin.sshkey.api.Constants;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.SignerException;
import org.apache.http.Header;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.impl.auth.RFC2617Scheme;
import org.apache.http.message.BasicHeader;

public final class Http4SSHKeyAuthScheme extends RFC2617Scheme {

    private Signer signer;

    public Http4SSHKeyAuthScheme(Signer signer) {
        this.signer = signer;
    }

    public String getSchemeName() {
        return Constants.SCHEME;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    public Header authenticate(Credentials credentials, HttpRequest request)
            throws AuthenticationException {

        String fingerprint = this.getParameter(Constants.FINGERPRINT);
        String nonce = this.getParameter(Constants.NONCE);

        Header hostHeader = request.getFirstHeader(Constants.HOST);
        Header userAgentHeader = request.getFirstHeader(Constants.USER_AGENT);
        String host = hostHeader != null ? hostHeader.getValue() : "";
        String userAgent = userAgentHeader != null ? userAgentHeader.getValue() : "";

        Challenge challenge = new Challenge(this.getRealm(), fingerprint, nonce, host, userAgent);

        try {
            Authorization authorization = this.signer.sign(challenge);
            if (authorization != null) {
                return new BasicHeader(Constants.AUTHORIZATION,
                                       authorization.toString());
            }
        } catch (SignerException e) {
            throw new AuthenticationException("Failed to sign challenge", e);
        }

        return null;
    }
}
