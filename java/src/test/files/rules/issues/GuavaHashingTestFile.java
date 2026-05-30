/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.security.Key;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reproduction of the pkg:maven/com.google.guava/guava@33.0.0-jre Hashing.java pattern.
 *
 * <p>In the real Hashing.java (lines 285-379), each hmacXxx(byte[] key) method passes a nested
 * {@code new SecretKeySpec(...)} directly as an argument to the overloaded hmacXxx(Key key)
 * variant. Each pair is separated by a multi-line javadoc comment.
 *
 * <p>Actual source lines in guava-33.0.0-jre Hashing.java:
 *
 * <ul>
 *   <li>line 306: {@code return hmacMd5(new SecretKeySpec(checkNotNull(key), "HmacMD5"));}
 *   <li>line 330: {@code return hmacSha1(new SecretKeySpec(checkNotNull(key), "HmacSHA1"));}
 *   <li>line 354: {@code return hmacSha256(new SecretKeySpec(checkNotNull(key), "HmacSHA256"));}
 *   <li>line 378: {@code return hmacSha512(new SecretKeySpec(checkNotNull(key), "HmacSHA512"));}
 * </ul>
 *
 * <p>This fixture uses only JDK types but preserves the exact structural pattern: nested {@code new
 * SecretKeySpec(...)} as a direct argument, methods separated by multi-line javadoc.
 */
public class GuavaHashingTestFile {

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the MD5 (128 hash bits) hash function and the given secret key.
     *
     * @param key the secret key
     * @throws IllegalArgumentException if the given key is inappropriate for initializing this MAC
     * @since 20.0
     */
    public static Key hmacMd5(Key key) {
        return key;
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the MD5 (128 hash bits) hash function and a SecretKeySpec created from the given byte array
     * and the MD5 algorithm.
     *
     * @param key the key material of the secret key
     * @since 20.0
     */
    public static Key hmacMd5(byte[] key) {
        return hmacMd5(new SecretKeySpec(key, "HmacMD5")); // Noncompliant {{(SecretKey) HMAC}}
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the SHA-1 (160 hash bits) hash function and the given secret key.
     *
     * @param key the secret key
     * @throws IllegalArgumentException if the given key is inappropriate for initializing this MAC
     * @since 20.0
     */
    public static Key hmacSha1(Key key) {
        return key;
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the SHA-1 (160 hash bits) hash function and a SecretKeySpec created from the given byte
     * array and the SHA-1 algorithm.
     *
     * @param key the key material of the secret key
     * @since 20.0
     */
    public static Key hmacSha1(byte[] key) {
        return hmacSha1(new SecretKeySpec(key, "HmacSHA1")); // Noncompliant {{(SecretKey) HMAC}}
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the SHA-256 (256 hash bits) hash function and the given secret key.
     *
     * @param key the secret key
     * @throws IllegalArgumentException if the given key is inappropriate for initializing this MAC
     * @since 20.0
     */
    public static Key hmacSha256(Key key) {
        return key;
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the SHA-256 (256 hash bits) hash function and a SecretKeySpec created from the given byte
     * array and the SHA-256 algorithm.
     *
     * @param key the key material of the secret key
     * @since 20.0
     */
    public static Key hmacSha256(byte[] key) {
        return hmacSha256(new SecretKeySpec(key, "HmacSHA256")); // Noncompliant {{(SecretKey) HMAC}}
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the SHA-512 (512 hash bits) hash function and the given secret key.
     *
     * @param key the secret key
     * @throws IllegalArgumentException if the given key is inappropriate for initializing this MAC
     * @since 20.0
     */
    public static Key hmacSha512(Key key) {
        return key;
    }

    /**
     * Returns a hash function implementing the Message Authentication Code (MAC) algorithm, using
     * the SHA-512 (512 hash bits) hash function and a SecretKeySpec created from the given byte
     * array and the SHA-512 algorithm.
     *
     * @param key the key material of the secret key
     * @since 20.0
     */
    public static Key hmacSha512(byte[] key) {
        return hmacSha512(new SecretKeySpec(key, "HmacSHA512")); // Noncompliant {{(SecretKey) HMAC}}
    }
}
