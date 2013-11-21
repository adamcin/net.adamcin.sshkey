package net.adamcin.sshkey.simple;

/**
* Created with IntelliJ IDEA.
* User: madamcin
* Date: 11/20/13
* Time: 5:48 PM
* To change this template use File | Settings | File Templates.
*/
public abstract class SignatureDecorator {
    abstract byte[] postSign(byte[] signatureBytes);
    abstract byte[] preVerify(byte[] signatureBytes);

    protected final byte[] extract(byte[] signatureBytes) {
        if (signatureBytes[0] == 0 && signatureBytes[1] == 0 && signatureBytes[2] == 0) {
            int i = 0;
            int j;
            j =     ((signatureBytes[i++] << 24) & 0xff000000) |
                    ((signatureBytes[i++] << 16) & 0x00ff0000) |
                    ((signatureBytes[i++] <<  8) & 0x0000ff00) |
                    ((signatureBytes[i++]      ) & 0x000000ff);
            i += j;
            j =     ((signatureBytes[i++] << 24) & 0xff000000) |
                    ((signatureBytes[i++] << 16) & 0x00ff0000) |
                    ((signatureBytes[i++] << 8 ) & 0x0000ff00) |
                    ((signatureBytes[i++]      ) & 0x000000ff);
            byte[] tmp = new byte[j];
            System.arraycopy(signatureBytes, i, tmp, 0, j);
            signatureBytes = tmp;
        }
        return signatureBytes;
    }

    public static final SignatureDecorator RSA = new SignatureDecorator() {
        @Override
        byte[] postSign(byte[] signatureBytes) {
            return signatureBytes;
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = extract(signatureBytes);
            return extracted;
        }
    };

    public static final SignatureDecorator DSA = new SignatureDecorator() {
        @Override
        byte[] postSign(byte[] signatureBytes) {
            return signatureBytes;
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = extract(signatureBytes);
            return extracted;
        }
    };
}
