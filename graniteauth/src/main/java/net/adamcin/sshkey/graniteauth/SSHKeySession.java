package net.adamcin.sshkey.graniteauth;

import com.adobe.granite.crypto.CryptoException;
import com.adobe.granite.crypto.CryptoSupport;
import net.adamcin.sshkey.commons.Challenge;

import javax.servlet.http.HttpServletRequest;

public final class SSHKeySession {
    private final Challenge challenge;
    private final String username;
    private final String remoteAddr;
    private final long timestamp;

    private SSHKeySession(Challenge challenge, String username, String remoteAddr, long timestamp) {
        this.challenge = challenge;
        this.username = username;
        this.remoteAddr = remoteAddr;
        this.timestamp = timestamp;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public String getUsername() {
        return username;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public boolean validateRequest(HttpServletRequest request, long maxAge) {
        return (System.currentTimeMillis() <= maxAge + this.timestamp)
                && this.remoteAddr.equals(getRemoteAddr(request))
                && this.challenge.getHost().equals(getHost(request))
                && this.challenge.getUserAgent().equals(getUserAgent(request));
    }

    private static String getHost(HttpServletRequest request) {
        return request.getHeader("Host") != null ? request.getHeader("Host") : "";
    }

    private static String getUserAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "";
    }

    private static String getRemoteAddr(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    public static SSHKeySession createSession(CryptoSupport cryptoSupport,
                                                    String username,
                                                    String fingerprint,
                                                    String realm,
                                                    HttpServletRequest request) throws
                                                                                                                                                                CryptoException {
        String remoteAddr = getRemoteAddr(request);
        String host = getHost(request);
        String userAgent = getUserAgent(request);
        Long timestamp = System.currentTimeMillis();

        StringBuilder raw = new StringBuilder();
        raw.append(username)
                .append(fingerprint)
                .append(realm)
                .append(remoteAddr)
                .append(host)
                .append(userAgent)
                .append(timestamp);

        String encrypted = cryptoSupport.protect(raw.toString());
        String token = encrypted.substring(1, encrypted.length() - 1);
        Challenge challenge = new Challenge(realm, fingerprint, token, host, userAgent);

        return new SSHKeySession(challenge, username, remoteAddr, timestamp);
    }
}
