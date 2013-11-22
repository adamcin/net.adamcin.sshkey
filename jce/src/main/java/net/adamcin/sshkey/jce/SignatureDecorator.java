package net.adamcin.sshkey.jce;

import net.adamcin.sshkey.api.Magic;

/**
 * Simple abstract class and key-format-specific adjustments to signatures performed by SSH clients.
 */
public abstract class SignatureDecorator {
    abstract byte[] postSign(byte[] signatureBytes);
    abstract byte[] preVerify(byte[] signatureBytes);

    public static final SignatureDecorator RSA = new SignatureDecorator() {
        @Override
        byte[] postSign(byte[] signatureBytes) {
            return signatureBytes;
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = Magic.extractSignature(signatureBytes);
            return extracted;
        }
    };

    public static final SignatureDecorator DSA = new SignatureDecorator() {
        @Override
        byte[] postSign(byte[] signatureBytes) {
            return Magic.encodeASN1(signatureBytes);
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = Magic.extractSignature(signatureBytes);
            return Magic.decodeASN1(extracted);
        }
    };
}
