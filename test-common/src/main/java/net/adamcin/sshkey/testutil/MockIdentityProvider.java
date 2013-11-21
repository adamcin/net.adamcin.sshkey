package net.adamcin.sshkey.testutil;

import net.adamcin.sshkey.api.Identity;
import net.adamcin.sshkey.api.IdentityProvider;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: madamcin
 * Date: 11/18/13
 * Time: 5:47 PM
 * To change this template use File | Settings | File Templates.
 */
public class MockIdentityProvider implements IdentityProvider {

    private MockIdentity mockIdentity;

    public MockIdentityProvider(String fingerprint) {
        this.mockIdentity = new MockIdentity(fingerprint);
    }

    public boolean contains(String fingerprint) {
        return mockIdentity.fingerprint.equals(fingerprint);
    }

    public Identity get(String fingerprint) {
        if (contains(fingerprint)) {
            return mockIdentity;
        }
        return null;
    }

    public Set<String> fingerprints() {
        return Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(mockIdentity.getFingerprint())));
    }
}
