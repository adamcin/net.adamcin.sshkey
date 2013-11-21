package net.adamcin.sshkey.simple;

import net.adamcin.sshkey.api.Identity;
import net.adamcin.sshkey.api.IdentityProvider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Simple loginId-agnostic implementation of {@link net.adamcin.sshkey.api.IdentityProvider} backed by a HashMap and
 * modified via {@link Collection} methods
 */
public class SimpleIdentityProvider implements IdentityProvider, Collection<Identity> {

    private final Map<String, Identity> _identities = new HashMap<String, Identity>();

    public SimpleIdentityProvider() {
    }

    public SimpleIdentityProvider(Collection<? extends Identity> identities) {
        this.addAll(identities);
    }

    public Set<String> fingerprints() {
        return Collections.unmodifiableSet(_identities.keySet());
    }

    public int size() {
        return _identities.size();
    }

    public boolean isEmpty() {
        return _identities.isEmpty();
    }

    public boolean contains(Object o) {
        return _identities.values().contains(o);
    }

    public Iterator<Identity> iterator() {
        return _identities.values().iterator();
    }

    public Object[] toArray() {
        return _identities.values().toArray();
    }

    public <T> T[] toArray(T[] a) {
        return _identities.values().toArray(a);
    }

    public boolean add(Identity identity) {
        if (identity == null || _identities.containsKey(identity.getFingerprint())) {
            return false;
        } else {
            return _identities.put(identity.getFingerprint(), identity) != null;
        }
    }

    public boolean remove(Object o) {
        return _identities.values().remove(o);
    }

    public boolean containsAll(Collection<?> c) {
        return _identities.values().containsAll(c);
    }

    public boolean addAll(Collection<? extends Identity> c) {
        boolean changed = false;

        if (c != null) {
            for (Identity i : c) {
                if (add(i)) {
                    changed = true;
                }
            }
        }

        return changed;
    }

    public boolean removeAll(Collection<?> c) {
        return _identities.values().removeAll(c);
    }

    public boolean retainAll(Collection<?> c) {
        return _identities.values().retainAll(c);
    }

    public void clear() {
        _identities.clear();
    }

    public boolean contains(String fingerprint) {
        return _identities.containsKey(fingerprint);
    }

    public Identity get(String fingerprint) {
        return _identities.get(fingerprint);
    }
}
