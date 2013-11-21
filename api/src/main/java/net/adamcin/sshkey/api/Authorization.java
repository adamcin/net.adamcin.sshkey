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

package net.adamcin.sshkey.api;

import java.io.Serializable;

/**
 * Representation of the "Authorization: SSHKey ..." header sent by the client in response to a {@link Challenge}
 */
public final class Authorization implements Serializable {

    private final String token;
    private final String signature;

    public Authorization(final String token, final String signature) {
        this.token = token;
        this.signature = signature;
    }

    public Authorization(String token, byte[] signatureBytes) {
        this.token = token;
        this.signature = Base64.toBase64String(signatureBytes);
    }

    public String getToken() {
        return token;
    }

    /**
     * @return the signature as a Base64-encoded string
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @return the signature as an unencoded byte array for verification using a {@link Verifier}
     */
    public byte[] getSignatureBytes() {
        return Base64.fromBase64String(this.signature);
    }

    public String getHeaderValue() {
        return Constants.SCHEME + " " + token + " " + signature;
    }

    @Override
    public String toString() {
        return getHeaderValue();
    }

    public static Authorization parse(String header) {
        if (header == null) {
            return null;
        }

        String[] parts = header.split(" ");

        if (parts.length != 3 && !Constants.SCHEME.equals(parts[0])) {
            return null;
        }

        String token = parts[1];
        String signature = parts[2];

        return new Authorization(token, signature);
    }
}
