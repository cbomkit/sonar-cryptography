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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Checks every identifier in {@link DotNetXmlAlgorithmUris}, in both spellings, against the W3C URI
 * and the {@code SignedXml} or {@code EncryptedXml} constant name. A typo in a table entry would
 * otherwise go unnoticed, because the rule tests exercise only a few of them.
 */
class DotNetXmlAlgorithmUrisTest {

    private static final DetectionLocation LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "DotNet");

    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final String DSIG_MORE = "http://www.w3.org/2001/04/xmldsig-more#";
    private static final String XMLENC = "http://www.w3.org/2001/04/xmlenc#";

    @Test
    void digests() {
        assertDigest("SHA-1", DSIG + "sha1", "XmlDsigSHA1Url");
        assertDigest("SHA-256", XMLENC + "sha256", "XmlDsigSHA256Url", "XmlEncSHA256Url");
        assertDigest("SHA-384", DSIG_MORE + "sha384", "XmlDsigSHA384Url");
        assertDigest("SHA-512", XMLENC + "sha512", "XmlDsigSHA512Url", "XmlEncSHA512Url");
        assertDigest("MD5", DSIG_MORE + "md5");
        assertDigest("RIPEMD-160", XMLENC + "ripemd160", "XmlDsigRIPEMD160Url");
    }

    @Test
    void rsaSignaturesAreSignWithDigestAndPkcs1() {
        assertSignature(
                "RSA-PKCS1-1.5-SHA-1", "SHA-1", "PKCS1", DSIG + "rsa-sha1", "XmlDsigRSASHA1Url");
        assertSignature(
                "RSA-PKCS1-1.5-SHA-256",
                "SHA-256",
                "PKCS1",
                DSIG_MORE + "rsa-sha256",
                "XmlDsigRSASHA256Url");
        assertSignature(
                "RSA-PKCS1-1.5-SHA-384",
                "SHA-384",
                "PKCS1",
                DSIG_MORE + "rsa-sha384",
                "XmlDsigRSASHA384Url");
        assertSignature(
                "RSA-PKCS1-1.5-SHA-512",
                "SHA-512",
                "PKCS1",
                DSIG_MORE + "rsa-sha512",
                "XmlDsigRSASHA512Url");
    }

    @Test
    void dsaAndEcdsaSignaturesHaveNoPadding() {
        assertSignature("DSA-SHA-1", "SHA-1", null, DSIG + "dsa-sha1", "XmlDsigDSAUrl");
        assertSignature("ECDSA-SHA-1", "SHA-1", null, DSIG_MORE + "ecdsa-sha1");
        assertSignature("ECDSA-SHA-256", "SHA-256", null, DSIG_MORE + "ecdsa-sha256");
        assertSignature("ECDSA-SHA-384", "SHA-384", null, DSIG_MORE + "ecdsa-sha384");
        assertSignature("ECDSA-SHA-512", "SHA-512", null, DSIG_MORE + "ecdsa-sha512");
    }

    @Test
    void hmacIdentifiersAreMacsNotSignatures() {
        assertMac("HMAC-SHA-1", DSIG + "hmac-sha1", "XmlDsigHMACSHA1Url");
        assertMac("HMAC-SHA-256", DSIG_MORE + "hmac-sha256");
        assertMac("HMAC-SHA-384", DSIG_MORE + "hmac-sha384");
        assertMac("HMAC-SHA-512", DSIG_MORE + "hmac-sha512");
    }

    @Test
    void encryptionAlgorithms() {
        assertEncryption("AES-128-CBC", XMLENC + "aes128-cbc", "XmlEncAES128Url");
        assertEncryption("AES-192-CBC", XMLENC + "aes192-cbc", "XmlEncAES192Url");
        assertEncryption("AES-256-CBC", XMLENC + "aes256-cbc", "XmlEncAES256Url");
        assertEncryption("DESede-CBC", XMLENC + "tripledes-cbc", "XmlEncTripleDESUrl");
        assertEncryption("DES-56-CBC", XMLENC + "des-cbc", "XmlEncDESUrl");
        assertEncryption("RSA-OAEP", XMLENC + "rsa-oaep-mgf1p", "XmlEncRSAOAEPUrl");
    }

    @Test
    void rsa15KeepsItsPkcs1Padding() {
        for (String id : List.of(XMLENC + "rsa-1_5", "XmlEncRSA15Url")) {
            final INode node = DotNetXmlAlgorithmUris.encryption(id, LOCATION).get();
            assertThat(node.asString()).as(id).isEqualTo("RSA");
            assertThat(node.getChildren().get(Padding.class).asString()).as(id).isEqualTo("PKCS1");
        }
    }

    @Test
    void rsaOaepKeepsItsSha1Digest() {
        final INode node =
                DotNetXmlAlgorithmUris.encryption(XMLENC + "rsa-oaep-mgf1p", LOCATION).get();
        final INode padding = node.getChildren().get(Padding.class);
        assertThat(padding).isNotNull();
        assertThat(padding.getChildren().get(MessageDigest.class).asString()).isEqualTo("SHA-1");
    }

    @Test
    void anIdentifierOfAnotherKindGivesNothing() {
        final String sha256 = XMLENC + "sha256";
        final String rsaSha256 = DSIG_MORE + "rsa-sha256";
        final String aes256 = XMLENC + "aes256-cbc";

        assertThat(DotNetXmlAlgorithmUris.signature(sha256, LOCATION)).isEmpty();
        assertThat(DotNetXmlAlgorithmUris.encryption(sha256, LOCATION)).isEmpty();
        assertThat(DotNetXmlAlgorithmUris.digest(rsaSha256, LOCATION)).isEmpty();
        assertThat(DotNetXmlAlgorithmUris.encryption(rsaSha256, LOCATION)).isEmpty();
        assertThat(DotNetXmlAlgorithmUris.digest(aes256, LOCATION)).isEmpty();
        assertThat(DotNetXmlAlgorithmUris.signature(aes256, LOCATION)).isEmpty();
    }

    @Test
    void unknownAndEmptyIdentifiersGiveNothing() {
        for (String id :
                List.of("", "urn:example:not-an-algorithm", "SHA256", "XmlDsigC14NTransformUrl")) {
            assertThat(DotNetXmlAlgorithmUris.digest(id, LOCATION)).as(id).isEmpty();
            assertThat(DotNetXmlAlgorithmUris.signature(id, LOCATION)).as(id).isEmpty();
            assertThat(DotNetXmlAlgorithmUris.encryption(id, LOCATION)).as(id).isEmpty();
        }
    }

    // ---------------------------------------------------------------------------------------

    private static void assertDigest(@Nonnull String expected, @Nonnull String... ids) {
        for (String id : ids) {
            final INode node = present(DotNetXmlAlgorithmUris.digest(id, LOCATION), id);
            assertThat(node.getKind()).as(id).isEqualTo(MessageDigest.class);
            assertThat(node.asString()).as(id).isEqualTo(expected);
        }
    }

    private static void assertSignature(
            @Nonnull String expectedAlgorithm,
            @Nonnull String expectedDigest,
            @Nullable String expectedPadding,
            @Nonnull String... ids) {
        for (String id : ids) {
            final INode node = present(DotNetXmlAlgorithmUris.signature(id, LOCATION), id);
            assertThat(node.asString()).as(id).isEqualTo(expectedAlgorithm);
            assertThat(node.hasChildOfType(Sign.class)).as(id).isPresent();
            assertThat(node.getChildren().get(MessageDigest.class).asString())
                    .as(id)
                    .isEqualTo(expectedDigest);
            if (expectedPadding == null) {
                assertThat(node.getChildren().get(Padding.class)).as(id).isNull();
            } else {
                assertThat(node.getChildren().get(Padding.class).asString())
                        .as(id)
                        .isEqualTo(expectedPadding);
            }
        }
    }

    private static void assertMac(@Nonnull String expected, @Nonnull String... ids) {
        for (String id : ids) {
            final INode node = present(DotNetXmlAlgorithmUris.signature(id, LOCATION), id);
            assertThat(node.getKind()).as(id).isEqualTo(Mac.class);
            assertThat(node.asString()).as(id).isEqualTo(expected);
        }
    }

    private static void assertEncryption(@Nonnull String expected, @Nonnull String... ids) {
        for (String id : ids) {
            final INode node = present(DotNetXmlAlgorithmUris.encryption(id, LOCATION), id);
            assertThat(node.asString()).as(id).isEqualTo(expected);
        }
    }

    @Nonnull
    private static INode present(@Nonnull Optional<INode> node, @Nonnull String id) {
        assertThat(node).as(id).isPresent();
        return node.get();
    }
}
