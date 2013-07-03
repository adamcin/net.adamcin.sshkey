package net.adamcin.sshkey.provider.jsch;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import net.adamcin.sshkey.api.Authorization;
import net.adamcin.sshkey.api.Challenge;
import net.adamcin.sshkey.api.Signer;
import net.adamcin.sshkey.api.SignerException;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 6/28/13
 * Time: 10:07 AM
 * To change this template use File | Settings | File Templates.
 */
public class JschSigner implements Signer {

    private final JSch jSch = new JSch();
    private final Map<String, Identity> identities = new HashMap<String, Identity>();

    public Set<String> getFingerprints() {
        Set<String> keySet = identities.keySet();
        return Collections.unmodifiableSet(new HashSet<String>(keySet));
    }

    public void addLocalKey(String path, String passphrase) throws SignerException {
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

    public void addLocalKey(String name, byte[] keyBlob, byte[] passphrase) throws SignerException {
        try {
            this.jSch.addIdentity(name, keyBlob, null, passphrase);

            reloadIdentities();
        } catch (JSchException e) {
            throw new SignerException("Failed to add identity", e);
        }
    }

    private void reloadIdentities() throws SignerException {

        identities.clear();

        Vector _identities = jSch.getIdentityRepository().getIdentities();
        if (_identities != null) {
            for (Object obj : _identities) {
                Identity ident = (Identity) obj;
                try {
                    String fingerprint = PublicKey.getKeyFingerprint(ident.getPublicKeyBlob());
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

            identity = this.identities.get(challenge.getFingerprint());

            if (identity != null) {
                byte[] signature = identity.getSignature(challenge.getHash());
                return new Authorization(challenge.getNonce(), signature);
            }
        }

        return null;
    }

    public void clear() throws SignerException {
        identities.clear();
        try {
            this.jSch.removeAllIdentity();
        } catch (JSchException e) {
            throw new SignerException("Failed to remove all identities", e);
        }
    }
}
