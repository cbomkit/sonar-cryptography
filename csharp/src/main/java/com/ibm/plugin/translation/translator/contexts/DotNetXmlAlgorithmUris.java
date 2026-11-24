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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps the algorithm URIs of {@code System.Security.Cryptography.Xml} to mapper nodes.
 *
 * <p>Both the W3C URI and the {@code SignedXml} or {@code EncryptedXml} constant name are accepted.
 * The three methods read an identifier as a digest, a signature or an encryption algorithm; an
 * identifier of another kind gives nothing.
 *
 * <p>Not mapped: AES key wrap, RSA-PSS and GCM, which the model cannot carry.
 */
public final class DotNetXmlAlgorithmUris {

    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String DSIG_MORE = "http://www.w3.org/2001/04/xmldsig-more#";
    private static final String XMLENC = "http://www.w3.org/2001/04/xmlenc#";

    private DotNetXmlAlgorithmUris() {
        // utility
    }

    /** A digest identifier, as in {@code Reference.DigestMethod}. */
    @Nonnull
    public static Optional<INode> digest(@Nonnull String id, @Nonnull DetectionLocation location) {
        return switch (id.trim()) {
            case DSIG + "sha1", "XmlDsigSHA1Url" -> Optional.of(new SHA(location));
            case XMLENC + "sha256", "XmlDsigSHA256Url", "XmlEncSHA256Url" ->
                    Optional.of(new SHA2(256, location));
            case DSIG_MORE + "sha384", "XmlDsigSHA384Url" -> Optional.of(new SHA2(384, location));
            case XMLENC + "sha512", "XmlDsigSHA512Url", "XmlEncSHA512Url" ->
                    Optional.of(new SHA2(512, location));
            case DSIG_MORE + "md5" -> Optional.of(new MD5(location));
            case XMLENC + "ripemd160", "XmlDsigRIPEMD160Url" ->
                    Optional.of(new RIPEMD(160, location));
            default -> Optional.empty();
        };
    }

    /**
     * A signature identifier, as in {@code SignedInfo.SignatureMethod}. RSA, DSA and ECDSA give a
     * {@code Sign} with the digest (and PKCS#1 padding for RSA); an HMAC gives a MAC.
     */
    @Nonnull
    public static Optional<INode> signature(
            @Nonnull String id, @Nonnull DetectionLocation location) {
        return switch (id.trim()) {
            case DSIG + "rsa-sha1", "XmlDsigRSASHA1Url" -> rsa(new SHA(location), location);
            case DSIG_MORE + "rsa-sha256", "XmlDsigRSASHA256Url" ->
                    rsa(new SHA2(256, location), location);
            case DSIG_MORE + "rsa-sha384", "XmlDsigRSASHA384Url" ->
                    rsa(new SHA2(384, location), location);
            case DSIG_MORE + "rsa-sha512", "XmlDsigRSASHA512Url" ->
                    rsa(new SHA2(512, location), location);
            case DSIG + "dsa-sha1", "XmlDsigDSAUrl" -> dsa(new SHA(location), location);
            case DSIG_MORE + "ecdsa-sha1" -> ecdsa(new SHA(location), location);
            case DSIG_MORE + "ecdsa-sha256" -> ecdsa(new SHA2(256, location), location);
            case DSIG_MORE + "ecdsa-sha384" -> ecdsa(new SHA2(384, location), location);
            case DSIG_MORE + "ecdsa-sha512" -> ecdsa(new SHA2(512, location), location);
            case DSIG + "hmac-sha1", "XmlDsigHMACSHA1Url" ->
                    Optional.of(new HMAC(new SHA(location)));
            case DSIG_MORE + "hmac-sha256" -> Optional.of(new HMAC(new SHA2(256, location)));
            case DSIG_MORE + "hmac-sha384" -> Optional.of(new HMAC(new SHA2(384, location)));
            case DSIG_MORE + "hmac-sha512" -> Optional.of(new HMAC(new SHA2(512, location)));
            default -> Optional.empty();
        };
    }

    /** An encryption identifier, as in {@code new EncryptionMethod(algorithm)}. */
    @Nonnull
    public static Optional<INode> encryption(
            @Nonnull String id, @Nonnull DetectionLocation location) {
        return switch (id.trim()) {
            case XMLENC + "aes128-cbc", "XmlEncAES128Url" ->
                    Optional.of(new AES(128, new CBC(location), location));
            case XMLENC + "aes192-cbc", "XmlEncAES192Url" ->
                    Optional.of(new AES(192, new CBC(location), location));
            case XMLENC + "aes256-cbc", "XmlEncAES256Url" ->
                    Optional.of(new AES(256, new CBC(location), location));
            // No key length is stated, so none is claimed.
            case XMLENC + "tripledes-cbc", "XmlEncTripleDESUrl" -> {
                final DESede node = new DESede(location);
                node.put(new CBC(location));
                yield Optional.of(node);
            }
            case XMLENC + "des-cbc", "XmlEncDESUrl" ->
                    Optional.of(new DES(new CBC(location), location));
            case XMLENC + "rsa-1_5", "XmlEncRSA15Url" -> {
                final RSA node = new RSA(location);
                node.put(new PKCS1(location));
                yield Optional.of(node);
            }
            // rsa-oaep-mgf1p is OAEP with SHA-1, fixed by the identifier
            case XMLENC + "rsa-oaep-mgf1p", "XmlEncRSAOAEPUrl" -> {
                final RSA node = new RSA(location);
                node.put(new OAEP(new SHA(location), location));
                yield Optional.of(node);
            }
            default -> Optional.empty();
        };
    }

    @Nonnull
    /**
     * The signature algorithms named by a {@code SignatureMethod} URI.
     *
     * <p>Such a URI names the algorithm as plainly as it names the digest -- {@code
     * xmldsig-more#rsa-sha256} is RSA with SHA-256 and PKCS#1 v1.5 -- so the node is rooted at the
     * algorithm, with the digest, the padding and the {@code Sign} as its children.
     *
     * <p>Rooting it at the {@code Sign} instead loses all of that. Neither {@code
     * CBOMOutputFile.add} nor {@code InventoryRule.report} does anything with a functionality: the
     * first replaces such a root by its children, so the padding (a {@code Property}) disappears
     * and only the digest becomes a component, reported as a digest rather than a signature; the
     * second raises no issue at all, because it reports only roots that are an algorithm, a
     * protocol or a key.
     */
    private static Optional<INode> rsa(
            @Nonnull MessageDigest digest, @Nonnull DetectionLocation location) {
        final RSA rsa = new RSA(Signature.class, location);
        rsa.put(digest);
        rsa.put(new PKCS1(location));
        rsa.put(new Sign(location));
        return Optional.of(rsa);
    }

    /** As {@link #rsa}, for the {@code dsa-*} URIs. */
    private static Optional<INode> dsa(
            @Nonnull MessageDigest digest, @Nonnull DetectionLocation location) {
        final DSA dsa = new DSA(digest);
        dsa.put(new Sign(location));
        return Optional.of(dsa);
    }

    /** As {@link #rsa}, for the {@code ecdsa-*} URIs. The curve is not named by the URI. */
    private static Optional<INode> ecdsa(
            @Nonnull MessageDigest digest, @Nonnull DetectionLocation location) {
        final ECDSA ecdsa = new ECDSA(location);
        ecdsa.put(digest);
        ecdsa.put(new Sign(location));
        return Optional.of(ecdsa);
    }
}
