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

package net.adamcin.sshkey.testutil;

import net.adamcin.sshkey.api.Algorithm;
import net.adamcin.sshkey.api.Constants;
import net.adamcin.sshkey.api.Key;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class MockKey implements Key {

    String fingerprint = null;

    public MockKey(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getId() {
        return fingerprint;
    }

    public boolean verify(Algorithm algorithm, byte[] challengeHash, byte[] signatureBytes) {
        return new StringBuilder(new String(signatureBytes, Constants.CHARSET)).reverse().toString().equals(new String(challengeHash, Constants.CHARSET));
    }

    public byte[] sign(Algorithm algorithm, byte[] challengeHash) {
        return mockSign(challengeHash);
    }

    public static byte[] mockSign(byte[] challengeHash) {
        return new StringBuilder(new String(challengeHash, Constants.CHARSET)).reverse().toString().getBytes(
                Constants.CHARSET
        );
    }

    public Set<Algorithm> getAlgorithms() {
        return new HashSet<Algorithm>(Arrays.asList(Algorithm.values()));
    }
}
