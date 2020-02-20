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

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Consumer;

/**
 * Credits: retep998
 * https://github.com/retep998/Vana/
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class AESCipher {

    public static final int DEFAULT_BLOCK_SIZE = 1460;

    private static final byte[] AES_KEY = {
            (byte) 0x13, 0, 0, 0,
            (byte) 0x08, 0, 0, 0,
            (byte) 0x06, 0, 0, 0,
            (byte) 0xB4, 0, 0, 0,
            (byte) 0x1B, 0, 0, 0,
            (byte) 0x0F, 0, 0, 0,
            (byte) 0x33, 0, 0, 0,
            (byte) 0x52, 0, 0, 0
    };

    public static final SecretKey KEY = new SecretKeySpec(AESCipher.AES_KEY, 0, 32, "AES");

    private final SecretKey key;
    private final MoeIV iv;

    private final SecureRandom random;
    private final Cipher cipher;

    private final boolean mode;

    public AESCipher(SecretKey key, MoeIV iv, SecureRandom random, boolean encryption) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.key = key;
        this.iv = iv;
        this.random = random;
        this.cipher = Cipher.getInstance("AES/OFB/NoPadding");

        this.mode = encryption;
    }

    public Cipher cipher() {
        return cipher;
    }

    public MoeIV iv() {
        return iv;
    }

    public void init() throws InvalidKeyException, InvalidAlgorithmParameterException {
        cipher.init(mode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, iv, random);
    }

    public void crypt(byte[] in, byte[] out) {
        crypt(in, out, Throwable::printStackTrace);
    }

    public void crypt(byte[] in, byte[] out, Consumer<Throwable> exceptionConsumer) {
        try {
            init();

            var size = in.length;
            var position = 0;
            var offset = 0;
            var input = 0;
            var first = 1;

            while (size > position) {
                offset = AESCipher.DEFAULT_BLOCK_SIZE - first * 4;
                input = size > (position + offset) ? offset : (size - position);

                cipher.doFinal(in, position, input, out, position);

                position += offset;
                if (first == 1)
                    first = 0;
            }
        } catch (ShortBufferException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | InvalidAlgorithmParameterException e) {
            exceptionConsumer.accept(e);
        }
    }

    public static AESCipher of(MoeIV iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
        return new AESCipher(KEY, iv, new SecureRandom(), true);
    }
}
