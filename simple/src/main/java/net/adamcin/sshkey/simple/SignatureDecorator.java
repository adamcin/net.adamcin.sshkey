package net.adamcin.sshkey.simple;

/**
 * Simple abstract class and key-format-specific adjustments to signatures performed by SSH clients.
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

            // sig is in ASN.1
            // SEQUENCE::={ r INTEGER, s INTEGER }
            int len = 0;
            int index = 3;
            len = signatureBytes[index++] & 0xff;
            byte[] r = new byte[len];
            System.arraycopy(signatureBytes, index, r, 0, r.length);
            index = index + len + 1;
            len = signatureBytes[index++] & 0xff;
            byte[] s = new byte[len];
            System.arraycopy(signatureBytes, index, s, 0, s.length);

            byte[] result = new byte[40];

            // result must be 40 bytes, but length of r and s may not be 20 bytes

            System.arraycopy(r,
                             (r.length > 20) ? 1 : 0,
                             result,
                             (r.length > 20) ? 0 : 20 - r.length,
                             (r.length > 20) ? 20 : r.length);
            System.arraycopy(s,
                             (s.length > 20) ? 1 : 0,
                             result,
                             (s.length > 20) ? 20 : 40 - s.length,
                             (s.length > 20) ? 20 : s.length);

            return result;
        }

        @Override
        byte[] preVerify(byte[] signatureBytes) {
            final byte[] extracted = extract(signatureBytes);

            // ASN.1
            int frst = ((extracted[0] & 0x80) != 0 ? 1 : 0);
            int scnd = ((extracted[20] & 0x80) != 0 ? 1 : 0);

            int length = extracted.length + 6 + frst + scnd;
            byte[] result = new byte[length];
            result[0] = (byte) 0x30;
            result[1] = (byte) 0x2c;
            result[1] += frst;
            result[1] += scnd;
            result[2] = (byte) 0x02;
            result[3] = (byte) 0x14;
            result[3] += frst;
            System.arraycopy(extracted, 0, result, 4 + frst, 20);
            result[4 + result[3]] = (byte) 0x02;
            result[5 + result[3]] = (byte) 0x14;
            result[5 + result[3]] += scnd;
            System.arraycopy(extracted, 20, result, 6 + result[3] + scnd, 20);
            return result;
        }
    };
}
