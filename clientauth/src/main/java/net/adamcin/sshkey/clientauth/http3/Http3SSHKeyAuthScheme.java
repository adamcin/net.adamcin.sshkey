package net.adamcin.sshkey.clientauth.http3;

import net.adamcin.sshkey.commons.Authorization;
import net.adamcin.sshkey.commons.Challenge;
import net.adamcin.sshkey.commons.Constants;
import net.adamcin.sshkey.commons.Signer;
import net.adamcin.sshkey.commons.SignerException;
import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.auth.AuthenticationException;
import org.apache.commons.httpclient.auth.RFC2617Scheme;

public final class Http3SSHKeyAuthScheme extends RFC2617Scheme {

    public String getSchemeName() {
        return Constants.SCHEME;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    public String authenticate(Credentials credentials, String method, String uri) throws AuthenticationException {
        throw new AuthenticationException("SSHKey authentication requires access to Host and User-Agent headers");
    }

    public String authenticate(Credentials credentials, HttpMethod method) throws AuthenticationException {
        if (credentials instanceof SignerCredentials) {
            SignerCredentials creds = (SignerCredentials) credentials;

            String fingerprint = this.getParameter(Constants.CHALLENGE_PARAM_FINGERPRINT);
            String sessionId = this.getParameter(Constants.CHALLENGE_PARAM_TOKEN);

            Header hostHeader = method.getRequestHeader(Constants.HEADER_HOST);
            Header userAgentHeader = method.getRequestHeader(Constants.HEADER_USER_AGENT);
            String host = hostHeader != null ? hostHeader.getValue() : "";
            String userAgent = userAgentHeader != null ? userAgentHeader.getValue() : "";

            Challenge challenge = new Challenge(this.getRealm(), fingerprint, sessionId, host, userAgent);

            try {
                Signer signer = creds.getSigner();
                if (signer != null) {
                    Authorization authorization = creds.getSigner().sign(challenge);
                    if (authorization != null) {
                        return authorization.toString();
                    }
                }
            } catch (SignerException e) {
                throw new AuthenticationException("Failed to sign challenge", e);
            }
        }

        return null;
    }
}
