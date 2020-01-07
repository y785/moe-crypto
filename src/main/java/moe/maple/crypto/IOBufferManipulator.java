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

/**
 * The copy pasta is strong in this one.
 * todo: Possibly optimize or just convert the real thing.
 * Credits: https://github.com/retep998/Vana
 * src/common/encrypted_packet_transformer.cpp
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class IOBufferManipulator {

    public static byte rotl(byte in, int count) {
        return (byte) (((in & 0xFF) << (count % 8) & 0xFF) | ((in & 0xFF) << (count % 8) >> 8));
    }

    public static byte rotr(byte in, int count) {
        var tmp = (((int) in & 0xFF) << 8) >>> (count % 8);
        return (byte) ((tmp & 0xFF) | (tmp >>> 8));
    }

    public static void decrypt(byte[] data, int length) {
        int j;
        byte a, b, c;
        for (int i = 0; i < 3; ++i) {
            b = 0;
            for (j = length; j > 0; --j) {
                c = data[j - 1];
                c = rotl(c, 3);
                c ^= 0x13;
                a = c;
                c ^= b;
                c -= j;
                c = rotr(c, 4);
                b = a;
                data[j - 1] = c;
            }
            b = 0;
            for (j = length; j > 0; --j) {
                c = data[length - j];
                c -= 0x48;
                c ^= 0xFF;
                c = rotl(c, j);
                a = c;
                c ^= b;
                c -= j;
                c = rotr(c, 3);
                b = a;
                data[length - j] = c;
            }
        }
    }

    public static void decrypt(byte[] data) {
        decrypt(data, data.length);
    }

    public static void encrypt(byte[] data, int length) {
        int j;
        byte a, c;
        for (int i = 0; i < 3; ++i) {
            a = 0;
            for(j = length; j > 0; --j) {
                c = data[length - j];
                c = rotl(c, 3);
                c+= j;
                c^= a;
                a = c;
                c = rotr(a, j);
                c^= 0xFF;
                c+= 0x48;
                data[length - j] = c;
            }
            a = 0;
            for (j = length; j > 0; --j) {
                c = data[j - 1];
                c = rotl(c, 4);
                c+= j;
                c^= a;
                a = c;
                c^= 0x13;
                c = rotr(c, 3);
                data[j - 1] = c;
            }
        }
    }

    public static void encrypt(byte[] data) {
        encrypt(data, data.length);
    }
}
