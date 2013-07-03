package net.adamcin.sshkey.api;

import java.util.ServiceLoader;

public abstract class VerifierFactory {
    public abstract Verifier getInstance();

    public static VerifierFactory getFactoryInstance() {
        return getFactoryInstance(VerifierFactory.class.getClassLoader());
    }

    public static VerifierFactory getFactoryInstance(ClassLoader classLoader) {
        if (classLoader == null) {
            for (VerifierFactory factory : ServiceLoader.load(VerifierFactory.class)) {
                if (factory != null) {
                    return factory;
                }
            }
        } else {
            for (VerifierFactory factory : ServiceLoader.load(VerifierFactory.class, classLoader)) {
                if (factory != null) {
                    return factory;
                }
            }
        }

        return null;
    }
}
