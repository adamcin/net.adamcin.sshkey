package net.adamcin.sshkey.provider.jsch;

import com.jcraft.jsch.Buffer;
import com.jcraft.jsch.Signature;
import com.jcraft.jsch.jce.SignatureDSA;

import java.util.Arrays;

final class PublicKeyDSA extends PublicKey {

    public static final String FORMAT = "ssh-dss";

    public PublicKeyDSA(String format, String encodedKey) {
        super(format, encodedKey);
    }

    @Override
    Signature getSignature() throws Exception {
        SignatureDSA signature = new SignatureDSA();

        Buffer buf = new Buffer(this.key);

        signature.init();
        buf.getString(); // read the format string first
        byte[] p = buf.getString();
        byte[] q = buf.getString();
        byte[] g = buf.getString();
        byte[] pub_array = buf.getString();
        signature.setPubKey(pub_array, p, q, g);
        return signature;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PublicKeyDSA)) {
            return false;
        }

        PublicKeyDSA otherKey = (PublicKeyDSA) obj;

        return Arrays.equals(this.key, otherKey.key);
    }

    @Override
    public int hashCode() {
        return FORMAT.hashCode() + Arrays.hashCode(this.key);
    }
}
