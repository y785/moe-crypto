/*
 * Copyright (C) 2019, y785, http://github.com/y785
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package moe.maple.crypto;

import javax.crypto.spec.IvParameterSpec;
import java.util.Random;

/**
 * What could go wrong
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class MoeIV extends IvParameterSpec {

    private static byte[] IV_GMS = new byte[] {
            (byte)0x4D, (byte)0x23, (byte)0xC7, (byte)0x2B
    };

    private static byte[] IV_MSEA = new byte[] {
            (byte)0xB9, (byte)0x7D, (byte)0x63, (byte)0xE9
    };

    private volatile byte[] iv;

    private MoeIV(byte[] iv, int offset, int len) {
        super(iv, offset, len);
    }

    public MoeIV(byte[] iv) {
        this(new byte[0], 0, 0);
        if (iv.length != 16)
            throw new IllegalArgumentException("IV length is invalid: " + iv.length);

        this.iv = iv;
    }

    @Override
    public byte[] getIV() {
        return iv;
    }

    public void shuffle() {
        IGCipher.innoHash(iv, 4, null);
        for (int i = 4; i < iv.length; i++)
            iv[i] = iv[i % 4];
    }

    public static MoeIV from(byte[] seed) {
        if (seed.length < 4)
            throw new IllegalArgumentException("IV length is invalid: " + seed.length);

        var iv = new byte[] {
                seed[0], seed[1], seed[2], seed[3],
                seed[0], seed[1], seed[2], seed[3],
                seed[0], seed[1], seed[2], seed[3],
                seed[0], seed[1], seed[2], seed[3],
        };
        return new MoeIV(iv);
    }

    public static MoeIV from(Random random) {
        var seed = new byte[4];
        random.nextBytes(seed);
        return from(seed);
    }

    public static MoeIV GMS() {
        return from(IV_GMS);
    }

    public static MoeIV MSEA() {
        return from(IV_MSEA);
    }
}
