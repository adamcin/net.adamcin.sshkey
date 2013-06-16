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
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.HttpParams;
import org.apache.http.util.CharArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSHKeyAuthScheme extends AuthSchemeBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(SSHKeyAuthScheme.class);

    public static final String CHALLENGE_PARAM_FINGERPRINT = "fingerprint";
    public static final String CHALLENGE_PARAM_SESSION_ID = "sessionId";

    private String realm;
    private Challenge challenge;
    private Signer signer;

    public SSHKeyAuthScheme(Signer signer, HttpParams httpParams) {
        this.signer = signer;
    }

    @Override
    protected void parseChallenge(CharArrayBuffer buffer, int beginIndex, int endIndex)
            throws MalformedChallengeException {

        String challengeString = buffer.substring(beginIndex, endIndex);
        LOGGER.error("[parseChallenge] challenge: {}", challengeString);

        this.challenge = Challenge.parseChallenge(challengeString);

        if (challenge != null) {
            this.realm = challenge.getRealm();
        } else {
            throw new MalformedChallengeException("Challenge must include realm and sessionId");
        }
    }

    public String getSchemeName() {
        return Constants.SCHEME_NAME;
    }

    public String getParameter(String name) {
        if (challenge == null) {
            return null;
        }

        if (CHALLENGE_PARAM_FINGERPRINT.equals(name)) {
            return this.challenge.getFingerprint();
        } else if (CHALLENGE_PARAM_SESSION_ID.equals(name)) {
            return this.challenge.getSessionId();
        }

        return null;
    }

    public String getRealm() {
        return this.realm;
    }

    public boolean isConnectionBased() {
        return false;
    }

    public boolean isComplete() {
        return true;
    }

    public Header authenticate(Credentials credentials, HttpRequest request)
            throws AuthenticationException {

        if (this.challenge != null) {
            try {
                Authorization authorization = this.signer.sign(this.challenge);
                if (authorization != null) {
                    return new BasicHeader(Constants.HEADER_AUTHORIZATION, authorization.toString());
                }
            } catch (SignerException e) {
                throw new AuthenticationException("Failed to sign challenge", e);
            }
        }

        return null;
    }
}
