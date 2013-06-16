package net.adamcin.sshkey.commons;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Verifier {

    private Map<String, PublicKey> authorizedKeys = new HashMap<String, PublicKey>();

    public synchronized String selectFingerprint(Collection<String> clientFingerprints) {
        if (clientFingerprints != null) {
            for (String clientFingerprint : clientFingerprints) {
                if (authorizedKeys.containsKey(clientFingerprint)) {
                    return clientFingerprint;
                }
            }
        }
        return null;
    }

    public void readAuthorizedKeys(File authorizedKeysFile) throws VerifierException {
        if (authorizedKeysFile != null) {
            Map<String, PublicKey> _keys = new HashMap<String, PublicKey>();
            InputStream authKeysStream = null;
            try {
                authKeysStream = new FileInputStream(authorizedKeysFile);
                List<PublicKey> keys = PublicKey.readKeys(new InputStreamReader(authKeysStream));
                for (PublicKey key : keys) {
                    String fingerprint = key.getFingerprint();
                    if (fingerprint == null) {
                        throw new VerifierException("Failed to generate fingerprint for key: " + key.toString());
                    }
                    _keys.put(key.getFingerprint(), key);
                }
                synchronized (this) {
                    authorizedKeys.putAll(_keys);
                }
            } catch (IOException e) {
                throw new VerifierException("Failed to read authorized_keys file: "
                                                    + authorizedKeysFile.getAbsolutePath(), e);
            } finally {
                if (authKeysStream != null) {
                    try {
                        authKeysStream.close();
                    } catch (IOException ignored) {}
                }
            }
        }
    }

    public boolean verify(Challenge challenge, Authorization authorization) throws VerifierException {
        if (challenge == null || authorization == null) {
            return false;
        }

        PublicKey key = null;
        synchronized (this) {
            key = authorizedKeys.get(challenge.getFingerprint());
        }

        if (key != null) {
            try {
                return key.verify(authorization);
            } catch (Exception e) {
                throw new VerifierException("Failed to verify signature", e);
            }
        }
        return false;
    }

    public synchronized void clear() {
        this.authorizedKeys.clear();
    }
}
