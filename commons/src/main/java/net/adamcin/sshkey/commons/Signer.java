package net.adamcin.sshkey.commons;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

public final class Signer {

    private final JSch jSch = new JSch();
    private final Map<String, Identity> identities = new HashMap<String, Identity>();

    public Set<String> getFingerprints() {
        Set<String> keySet = null;
        synchronized (this) {
            keySet = identities.keySet();
        }
        return Collections.unmodifiableSet(new HashSet<String>(keySet));
    }

    public synchronized void addLocalKey(String path, String passphrase) throws SignerException {
        try {
            if (passphrase != null) {
                this.jSch.addIdentity(path, passphrase);
            } else {
                this.jSch.addIdentity(path);
            }

            reloadIdentities();
        } catch (JSchException e) {
            throw new SignerException("Failed to add identity", e);
        }
    }

    private synchronized void reloadIdentities() throws SignerException {
        identities.clear();

        Vector _identities = jSch.getIdentityRepository().getIdentities();
        if (_identities != null) {
            for (Object obj : _identities) {
                Identity ident = (Identity) obj;
                try {
                    String fingerprint = Util.getKeyFingerprint(ident.getPublicKeyBlob());
                    identities.put(fingerprint, ident);
                } catch (Exception e) {
                    throw new SignerException("Failed to construct fingerprint for identity: " + ident.getName(), e);
                }
            }
        }
    }

    public Authorization sign(Challenge challenge) throws SignerException {
        if (challenge != null) {
            Identity identity = null;

            synchronized (this) {
                identity = this.identities.get(challenge.getFingerprint());
            }

            if (identity != null) {
                String sessionId = challenge.getSessionId();
                String signature = Util.toBase64(identity.getSignature(sessionId.getBytes()));
                return new Authorization(sessionId, signature);
            }
        }

        return null;
    }

    public synchronized void clear() throws VerifierException {
        identities.clear();
        try {
            this.jSch.removeAllIdentity();
        } catch (JSchException e) {
            throw new VerifierException("Failed to remove all identities", e);
        }
    }
}
