package net.adamcin.sshkey.api;

import java.util.ServiceLoader;

/**
 * Abstract factory
 */
public abstract class SignerFactory {
    public abstract Signer getInstance();

    public static SignerFactory getFactoryInstance() {
        return getFactoryInstance(SignerFactory.class.getClassLoader());
    }

    public static SignerFactory getFactoryInstance(ClassLoader classLoader) {
        if (classLoader == null) {
            for (SignerFactory factory : ServiceLoader.load(SignerFactory.class)) {
                if (factory != null) {
                    return factory;
                }
            }
        } else {
            for (SignerFactory factory : ServiceLoader.load(SignerFactory.class, classLoader)) {
                if (factory != null) {
                    return factory;
                }
            }
        }

        return null;
    }
}
