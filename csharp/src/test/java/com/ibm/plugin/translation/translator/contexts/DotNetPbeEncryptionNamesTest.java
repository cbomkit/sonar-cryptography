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

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Checks every member name in {@link DotNetPbeEncryptionNames}: the scheme each one selects, the
 * cipher below it and, for the {@code Pkcs12ExportPbeParameters} members, the hash. Names that
 * select nothing, such as {@code Default}, must give no scheme.
 */
class DotNetPbeEncryptionNamesTest {

    private static final DetectionLocation LOCATION =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "DotNet");

    @Test
    void aesMembersGivePbes2() {
        assertScheme("Aes128Cbc", "PBES2", "AES-128-CBC", null);
        assertScheme("Aes192Cbc", "PBES2", "AES-192-CBC", null);
        assertScheme("Aes256Cbc", "PBES2", "AES-256-CBC", null);
    }

    @Test
    void tripleDesMemberGivesPkcs12() {
        assertScheme("TripleDes3KeyPkcs12", "PKCS12", "DESede168-CBC", null);
    }

    @Test
    void pkcs12ExportMembersAlsoNameTheHash() {
        assertScheme("Pbes2Aes256Sha256", "PBES2", "AES-256-CBC", "SHA-256");
        assertScheme("Pkcs12TripleDesSha1", "PKCS12", "DESede168-CBC", "SHA-1");
    }

    @Test
    void namesThatSelectNothingGiveNoScheme() {
        for (String name : List.of("Default", "Unknown", "", "aes256cbc", "SHA256", "Aes512Cbc")) {
            assertThat(DotNetPbeEncryptionNames.parse(name, LOCATION)).as(name).isEmpty();
        }
    }

    private static void assertScheme(
            @Nonnull String name,
            @Nonnull String expectedScheme,
            @Nonnull String expectedCipher,
            @Nullable String expectedDigest) {
        final INode node = DotNetPbeEncryptionNames.parse(name, LOCATION).orElseThrow();
        assertThat(node.getKind()).as(name).isEqualTo(PasswordBasedEncryption.class);
        assertThat(node.asString()).as(name).startsWith(expectedScheme);
        assertThat(node.getChildren().get(BlockCipher.class).asString())
                .as(name)
                .isEqualTo(expectedCipher);
        final INode digest = node.getChildren().get(MessageDigest.class);
        if (expectedDigest == null) {
            assertThat(digest).as(name).isNull();
        } else {
            assertThat(digest.asString()).as(name).isEqualTo(expectedDigest);
        }
    }
}
