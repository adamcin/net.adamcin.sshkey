/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

package net.adamcin.sshkey.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Instance of a Signer, used by an HTTP client to sign a {@link Challenge} and create an {@link Authorization}
 */
public final class Signer {
    private static final Logger LOGGER = LoggerFactory.getLogger(Signer.class);

    private final IdentityProvider identityProvider;

    public Signer() {
        this(null);
    }

    public Signer(IdentityProvider identityProvider) {
        this.identityProvider = identityProvider != null ? identityProvider : Constants.EMPTY_PROVIDER;
    }

    public IdentityProvider getIdentityProvider() {
        return identityProvider;
    }

    /**
     * @return a set of public key fingerprints to offer in client HTTP request
     */
    public Set<String> getFingerprints() {
        Set<String> fingerprints = new HashSet<String>();
        Set<String> _fingerprints = this.identityProvider.fingerprints();
        if (_fingerprints != null) {
            for (String fingerprint : _fingerprints) {
                if (Constants.validateFingerprint(fingerprint)) {
                    fingerprints.add(fingerprint);
                } else {
                    LOGGER.info("[getFingerprints] fingerprint is invalid: {}", fingerprint);
                }
            }
        }
        return Collections.unmodifiableSet(fingerprints);
    }

    /**
     * Signs a {@link Challenge} and returns an {@link Authorization} header
     * @param challenge the challenge header to be signed
     * @return a signed SSHKey {@link Authorization} header or null if no identities could sign the {@link Challenge}
     */
    public Authorization sign(Challenge challenge) {
        if (challenge != null) {

            Identity identity = this.identityProvider.get(challenge.getFingerprint());

            if (identity != null) {
                byte[] signature = identity.sign(challenge.getHashBytes());

                if (signature != null) {
                    return new Authorization(challenge.getNonce(), signature);
                }
            }
        }

        return null;
    }
}
