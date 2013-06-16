package net.adamcin.sshkey.graniteauth;

import com.adobe.granite.crypto.CryptoException;
import com.adobe.granite.crypto.CryptoSupport;
import net.adamcin.sshkey.commons.Challenge;

import javax.servlet.http.HttpServletRequest;

public final class SSHKeySession {
    private final Challenge challenge;
    private final String username;
    private final String remoteAddr;
    private final String serverName;
    private final int serverPort;
    private final long timestamp;

    private SSHKeySession(Challenge challenge, String username, HttpServletRequest request, long timestamp) {
        this.challenge = challenge;
        this.username = username;
        this.remoteAddr = request.getRemoteAddr();
        this.serverName = request.getServerName();
        this.serverPort = request.getServerPort();
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
        return (System.currentTimeMillis() <= maxAge + this.timestamp) && this.remoteAddr.equals(request.getRemoteAddr())
                && this.serverName.equals(request.getServerName())
                && this.serverPort == request.getServerPort();
    }

    public static final SSHKeySession createSession(CryptoSupport cryptoSupport,
                                                    String username,
                                                    String fingerprint,
                                                    String realm,
                                                    HttpServletRequest request) throws
                                                                                                                                                                CryptoException {
        String remoteAddr = request.getRemoteAddr();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        Long timestamp = System.currentTimeMillis();
        String raw = new StringBuilder(username).append(fingerprint).append(realm)
                .append(remoteAddr).append(serverName).append(serverPort)
                .append(timestamp).toString();
        String encrypted = cryptoSupport.protect(raw);
        String sessionId = encrypted.substring(1, encrypted.length() - 1);
        Challenge challenge = new Challenge(realm, fingerprint, sessionId);
        return new SSHKeySession(challenge, username, request, timestamp);
    }
}
