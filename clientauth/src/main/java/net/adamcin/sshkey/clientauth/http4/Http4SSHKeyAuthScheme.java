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
import org.apache.http.params.HttpParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Http4SSHKeyAuthScheme extends RFC2617Scheme {
    private static final Logger LOGGER = LoggerFactory.getLogger(Http4SSHKeyAuthScheme.class);

    private Signer signer;

    public Http4SSHKeyAuthScheme(Signer signer, HttpParams httpParams) {
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

        Header hostHeader = request.getFirstHeader("Host");
        Header userAgentHeader = request.getFirstHeader("User-Agent");
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
