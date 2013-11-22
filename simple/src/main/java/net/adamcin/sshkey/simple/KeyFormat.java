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

package net.adamcin.sshkey.simple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;

/**
 *
 */
public enum KeyFormat {

    SSH_DSS("ssh-dss", "DSA", "SHA1withDSA", FingerprintGenerator.DSA, SignatureDecorator.DSA),
    SSH_RSA("ssh-rsa", "RSA", "SHA1withRSA", FingerprintGenerator.RSA, SignatureDecorator.RSA),
    UNKOWN("_unknown_", "_unknown_", "_unknown_", new FingerprintGenerator() {
        @Override String getFingerprint(PublicKey publicKey) { return ""; }
    }, new SignatureDecorator() {
        @Override byte[] postSign(byte[] signatureBytes) { return signatureBytes; }
        @Override byte[] preVerify(byte[] signatureBytes) { return signatureBytes; }
    });

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyFormat.class);

    private final String identifier;
    private final String keyAlgorithm;
    private final String signatureAlgorithm;
    private final FingerprintGenerator fingerprintGenerator;
    private final SignatureDecorator signatureDecorator;

    private KeyFormat(String identifier, String keyAlgorithm, String signatureAlgorithm,
                      FingerprintGenerator fingerprintGenerator, SignatureDecorator signatureDecorator) {
        this.identifier = identifier;
        this.keyAlgorithm = keyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.fingerprintGenerator = fingerprintGenerator;
        this.signatureDecorator = signatureDecorator;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(getKeyAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            // should not happen in standard JVM
            e.printStackTrace(System.err);
        }

        return null;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getFingerprint(PublicKey publicKey) {
        return fingerprintGenerator.getFingerprint(publicKey);
    }

    public Signature getSignatureInstance() {
        try {
            return Signature.getInstance(getSignatureAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("[getSignatureInstance] failed to get signature instance.", e);
        }

        return null;
    }

    public byte[] postSign(byte[] signatureBytes) {
        return signatureDecorator.postSign(signatureBytes);
    }

    public byte[] preVerify(byte[] signatureBytes) {
        return signatureDecorator.preVerify(signatureBytes);
    }

    public static KeyFormat forIdentifier(String identifier) {
        for (KeyFormat format : KeyFormat.values()) {
            if (format.getIdentifier().equals(identifier)) {
                return format;
            }
        }

        return UNKOWN;
    }

}
