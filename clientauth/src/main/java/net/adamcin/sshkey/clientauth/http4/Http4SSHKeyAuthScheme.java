package net.adamcin.sshkey.clientauth.http4;

import net.adamcin.sshkey.commons.Authorization;
import net.adamcin.sshkey.commons.Challenge;
import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;
import net.adamcin.sshkey.commons.SignerException;
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

        String fingerprint = this.getParameter(Constants.CHALLENGE_PARAM_FINGERPRINT);
        String token = this.getParameter(Constants.CHALLENGE_PARAM_TOKEN);

        Header hostHeader = request.getFirstHeader(Constants.HEADER_HOST);
        Header userAgentHeader = request.getFirstHeader(Constants.HEADER_USER_AGENT);
        String host = hostHeader != null ? hostHeader.getValue() : "";
        String userAgent = userAgentHeader != null ? userAgentHeader.getValue() : "";

        Challenge challenge = new Challenge(this.getRealm(), fingerprint, token, host, userAgent);

        try {
            Authorization authorization = this.signer.sign(challenge);
            if (authorization != null) {
                return new BasicHeader(Constants.HEADER_AUTHORIZATION,
                                       authorization.toString());
            }
        } catch (SignerException e) {
            throw new AuthenticationException("Failed to sign challenge", e);
        }

        return null;
    }
}
