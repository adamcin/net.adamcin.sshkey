package net.adamcin.sshkey.api;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Simple implementation of {@link net.adamcin.sshkey.api.Keychain} backed by a HashMap and
 * modified via {@link Collection} methods
 */
public class DefaultKeychain implements Keychain, Collection<Key> {

    private final Map<String, Key> _identities = new HashMap<String, Key>();

    public DefaultKeychain() {
    }

    public DefaultKeychain(Collection<? extends Key> identities) {
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

    public Iterator<Key> iterator() {
        return _identities.values().iterator();
    }

    public Object[] toArray() {
        return _identities.values().toArray();
    }

    public <T> T[] toArray(T[] a) {
        return _identities.values().toArray(a);
    }

    public boolean add(Key key) {
        if (key == null || _identities.containsKey(key.getFingerprint())) {
            return false;
        } else {
            return _identities.put(key.getFingerprint(), key) != null;
        }
    }

    public boolean remove(Object o) {
        return _identities.values().remove(o);
    }

    public boolean containsAll(Collection<?> c) {
        return _identities.values().containsAll(c);
    }

    public boolean addAll(Collection<? extends Key> c) {
        boolean changed = false;

        if (c != null) {
            for (Key i : c) {
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

    public Key get(String fingerprint) {
        return _identities.get(fingerprint);
    }
}
