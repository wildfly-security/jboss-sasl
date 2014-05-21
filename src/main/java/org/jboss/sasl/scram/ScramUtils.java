/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.sasl.scram;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jboss.sasl.util.ByteStringBuilder;
import org.jboss.sasl.util.StringPrep;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramUtils {
    private static final byte[] randomCharDictionary;

    static {
        byte[] dict = new byte[93];
        int i = 0;
        for (byte c = '!'; c < ','; c ++) {
            dict[i ++] = c;
        }
        for (byte c = ',' + 1; c < 127; c ++) {
            dict[i ++] = c;
        }
        assert i == dict.length;
        randomCharDictionary = dict;
    }

    static final byte[] CLIENT_KEY_BYTES = "Client Key".getBytes(StandardCharsets.UTF_8);
    static final byte[] SERVER_KEY_BYTES = "Server Key".getBytes(StandardCharsets.UTF_8);

    public static void generateRandomString(StringBuilder b, int length, Random random) {
        for (int i = 0; i < length; i ++) {
            b.append(randomCharDictionary[random.nextInt(93)]);
        }
    }

    public static byte[] generateRandomString(int length, Random random) {
        final byte[] chars = new byte[length];
        for (int i = 0; i < length; i ++) {
            chars[i] = randomCharDictionary[random.nextInt(93)];
        }
        return chars;
    }

    public static int parsePosInt(byte[] src, int offset, int len) {
        int count = 1;
        int a, c;
        if (len == 0) {
            throw new NumberFormatException("Empty number");
        }
        c = src[offset];
        if (c == ',') {
            throw new NumberFormatException("Empty number");
        }
        if (c >= '1' && c <= '9') {
            a = c - '0';
        } else {
            throw new NumberFormatException("Invalid numeric character");
        }
        do {
            c = src[offset + count++];
            if (c >= '0' && c <= '9') {
                a = (a << 3) + (a << 1) + (c - '0');
                if (a < 0) {
                    throw new NumberFormatException("Too big");
                }
            } else if (c == ',') {
                return a;
            } else {
                throw new NumberFormatException("Invalid numeric character");
            }
        } while (count < len);
        return a;
    }

    public static int parsePosInt(byte[] src, int offset) {
        return parsePosInt(src, offset, src.length - offset);
    }

    public static int decimalDigitCount(int num) {
        if (num < 10) return 1;
        if (num < 100) return 2;
        if (num < 1000) return 3;
        if (num < 10000) return 4;
        if (num < 100000) return 5;
        if (num < 1000000) return 6;
        if (num < 10000000) return 7;
        if (num < 100000000) return 8;
        if (num < 1000000000) return 9;
        return 10;
    }

    public static byte[] calculateHi(Mac mac, char[] password, byte[] salt, int saltOffs, int saltLen, int iterationCount) throws InvalidKeyException {
        try {
            final ByteStringBuilder b = new ByteStringBuilder();
            StringPrep.encode(password, b, StringPrep.PROFILE_SASL_QUERY);
            mac.init(new SecretKeySpec(b.toArray(), mac.getAlgorithm()));
            mac.update(salt, saltOffs, saltLen);
            mac.update((byte) 1);
            mac.update((byte) 0);
            mac.update((byte) 0);
            mac.update((byte) 0);
            byte[] h = mac.doFinal();
            byte[] u = h;
            for (int i = 2; i <= iterationCount; i ++) {
                u = mac.doFinal(u);
                xor(h, u);
            }
            return h;
        } finally {
            mac.reset();
        }
    }

    public static void xor(byte[] key, byte val) {
        for (int i = 0; i < key.length; i++) {
            key[i] ^= val;
        }
    }

    public static void xor(final byte[] hash, final byte[] input) {
        assert hash.length == input.length;
        for (int i = 0; i < hash.length; i++) {
            hash[i] ^= input[i];
        }
    }
}
