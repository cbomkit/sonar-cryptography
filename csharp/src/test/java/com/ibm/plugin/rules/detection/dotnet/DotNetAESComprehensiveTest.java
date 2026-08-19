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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.BlockSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive test for all AES-related detection rules (DotNetAES.java).
 *
 * <p>Covers all five AES-related classes and their complete API surface:
 *
 * <ul>
 *   <li>Aes (abstract base)
 *   <li>AesManaged, AesCng, AesCryptoServiceProvider (derived from Aes)
 *   <li>AesGcm, AesCcm (AEAD, separate class hierarchy)
 * </ul>
 *
 * <p>Finding mapping (one finding per test method in DotNetAESComprehensiveTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–7):
 *   0  TestAesCreate                → AES
 *   1  TestAesCreateNamed           → AES
 *   2  TestAesManaged               → AES
 *   3  TestAesCng                   → AES
 *   4  TestAesCngNamed              → AES
 *   5  TestAesCsp                   → AES
 *   6  TestAesGcm                   → AES
 *   7  TestAesCcm                   → AES
 *
 * Section 2 – property setters (findings 8–22):
 *   8  TestPropertyModeCBC          → AES-CBC
 *   9  TestPropertyModeECB          → AES-ECB
 *   10 TestPropertyModeCFB          → AES-CFB
 *   11 TestPropertyModeOFB          → AES-OFB
 *   12 TestPropertyModeCTS          → AES-CTS
 *   13 TestPropertyKeySize128       → AES-128
 *   14 TestPropertyKeySize192       → AES-192
 *   15 TestPropertyKeySize256       → AES-256
 *   16 TestPropertyPaddingPKCS7     → AES-PKCS7
 *   17 TestPropertyPaddingNone      → AES-None
 *   18 TestPropertyPaddingZeros     → AES-Zeros
 *   19 TestPropertyPaddingANSIX923  → AES-ANSIX923
 *   20 TestPropertyFeedbackSize     → AES (BlockSize=128 detected, merged into default)
 *   21 TestPropertyIV               → AES (no IV rule)
 *   22 TestPropertyKey              → AES (no Key rule)
 *
 * Section 3 – CreateEncryptor/CreateDecryptor (findings 23–26):
 *   23 TestCreateEncryptorNoArgs     → AES + Encrypt
 *   24 TestCreateEncryptorWithArgs   → AES + Encrypt
 *   25 TestCreateDecryptorNoArgs     → AES + Decrypt
 *   26 TestCreateDecryptorWithArgs   → AES + Decrypt
 *
 * Section 4 – direct encrypt (findings 27–29):
 *   27 TestEncryptCbc               → AES-CBC-PKCS7
 *   28 TestEncryptEcb               → AES-ECB-None
 *   29 TestEncryptCfb               → AES-CFB-None
 *
 * Section 5 – direct decrypt (findings 30–32):
 *   30 TestDecryptCbc               → AES-CBC-PKCS7
 *   31 TestDecryptEcb               → AES-ECB-None
 *   32 TestDecryptCfb               → AES-CFB-None
 *
 * Section 6 – Try* variants (findings 33–38):
 *   33 TestTryEncryptCbc            → AES-CBC-PKCS7
 *   34 TestTryDecryptCbc            → AES-CBC-PKCS7
 *   35 TestTryEncryptEcb            → AES-ECB-None
 *   36 TestTryDecryptEcb            → AES-ECB-None
 *   37 TestTryEncryptCfb            → AES-CFB-None
 *   38 TestTryDecryptCfb            → AES-CFB-None
 *
 * Section 7 – key/IV generation (findings 39–40):
 *   39 TestGenerateKey              → AES + KeyGeneration
 *   40 TestGenerateIV               → AES + Generate
 *
 * Section 8 – AesGcm AEAD ops (findings 41–42):
 *   41 TestAesGcmEncrypt            → AES + Encrypt
 *   42 TestAesGcmDecrypt            → AES + Decrypt
 *
 * Section 9 – AesCcm AEAD ops (findings 43–44):
 *   43 TestAesCcmEncrypt            → AES + Encrypt
 *   44 TestAesCcmDecrypt            → AES + Decrypt
 *
 * Section 10 – combined usage patterns (findings 45–52):
 *   45 TestAesCbcFullFlow           → AES-256-CBC-PKCS7 + Encrypt
 *   46 TestAesCngEncryptCbc         → AES-CBC-PKCS7
 *   47 TestAesCspDecryptCbc         → AES-CBC-PKCS7
 *   48 TestAesManagedCfbFeedback    → AES-CFB-None
 *   49 TestAesCbcWithEncryptorOverload → AES + Encrypt
 *   50 TestAesEcbEncrypt            → AES-ECB-None
 *   51 TestAesGcmFullFlow           → AES + Encrypt
 *   52 TestAesCcmFullFlow           → AES + Encrypt
 * </pre>
 */
class DotNetAESComprehensiveTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetAESComprehensiveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be AES
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("AES");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only AES, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2, 3, 4, 5, 6, 7 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("AES");
            }

            // -----------------------------------------------------------------
            // Section 2a: property Mode setters
            // -----------------------------------------------------------------
            case 8 -> assertModeFindings(detectionStore, nodes, "CBC", "AES-CBC");
            case 9 -> assertModeFindings(detectionStore, nodes, "ECB", "AES-ECB");
            case 10 -> assertModeFindings(detectionStore, nodes, "CFB", "AES-CFB");
            case 11 -> assertModeFindings(detectionStore, nodes, "OFB", "AES-OFB");
            case 12 -> assertModeFindings(detectionStore, nodes, "CTS", "AES-CTS");

            // -----------------------------------------------------------------
            // Section 2b: property KeySize setters
            // -----------------------------------------------------------------
            case 13 -> assertKeySizeFindings(detectionStore, nodes, "128", "AES-128");
            case 14 -> assertKeySizeFindings(detectionStore, nodes, "192", "AES-192");
            case 15 -> assertKeySizeFindings(detectionStore, nodes, "256", "AES-256");

            // -----------------------------------------------------------------
            // Section 2c: property Padding setters
            // -----------------------------------------------------------------
            case 16 -> assertPaddingFindings(detectionStore, nodes, "PKCS7", "AES-PKCS7");
            case 17 -> assertPaddingFindings(detectionStore, nodes, "None", "AES-None");
            case 18 -> assertPaddingFindings(detectionStore, nodes, "Zeros", "AES-Zeros");
            case 19 -> assertPaddingFindings(detectionStore, nodes, "ANSIX923", "AES-ANSIX923");

            // -----------------------------------------------------------------
            // Section 2d: FeedbackSize setter — BlockSize(128) detected but
            // matches the default AES block size so node string stays "AES"
            // -----------------------------------------------------------------
            case 20 -> {
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> fbStore =
                        getStoreOfValueType(BlockSize.class, detectionStore.getChildren());
                assertThat(fbStore).isNotNull();
                assertThat(fbStore.getDetectionValues()).hasSize(1);
                assertThat(fbStore.getDetectionValues().get(0).asString()).isEqualTo("128");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("AES");
            }

            // -----------------------------------------------------------------
            // Section 2e: IV and Key setters — no detection rules for these
            // -----------------------------------------------------------------
            case 21, 22 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("AES");
            }

            // -----------------------------------------------------------------
            // Section 3: CreateEncryptor / CreateDecryptor
            // -----------------------------------------------------------------
            case 23, 24 -> assertEncryptFindings(detectionStore, nodes, "AES");
            case 25, 26 -> assertDecryptFindings(detectionStore, nodes, "AES");

            // -----------------------------------------------------------------
            // Section 4: direct mode-specific encrypt
            // -----------------------------------------------------------------
            case 27 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "AES-CBC-PKCS7");
            case 28 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "AES-ECB-None");
            case 29 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "AES-CFB-None");

            // -----------------------------------------------------------------
            // Section 5: direct mode-specific decrypt
            // -----------------------------------------------------------------
            case 30 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "AES-CBC-PKCS7");
            case 31 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "AES-ECB-None");
            case 32 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "AES-CFB-None");

            // -----------------------------------------------------------------
            // Section 6: Try* variants
            // -----------------------------------------------------------------
            case 33, 34 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "AES-CBC-PKCS7");
            case 35, 36 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "AES-ECB-None");
            case 37, 38 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "AES-CFB-None");

            // -----------------------------------------------------------------
            // Section 7: GenerateKey / GenerateIV
            // -----------------------------------------------------------------
            case 39 -> {
                // aes.GenerateKey() → KeyGeneration functionality node
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        genKeyStore =
                                getStoreOfValueType(
                                        ValueAction.class, detectionStore.getChildren());
                assertThat(genKeyStore).isNotNull();
                assertThat(genKeyStore.getDetectionValues().get(0).asString())
                        .isEqualTo("GenerateKey");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).getChildren().get(KeyGeneration.class)).isNotNull();
            }
            case 40 -> {
                // aes.GenerateIV() → Generate functionality node
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                        genIvStore =
                                getStoreOfValueType(
                                        ValueAction.class, detectionStore.getChildren());
                assertThat(genIvStore).isNotNull();
                assertThat(genIvStore.getDetectionValues().get(0).asString())
                        .isEqualTo("GenerateIV");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).getChildren().get(Generate.class)).isNotNull();
            }

            // -----------------------------------------------------------------
            // Section 8: AesGcm AEAD operations
            // -----------------------------------------------------------------
            case 41 -> assertEncryptFindings(detectionStore, nodes, "AES");
            case 42 -> assertDecryptFindings(detectionStore, nodes, "AES");

            // -----------------------------------------------------------------
            // Section 9: AesCcm AEAD operations
            // -----------------------------------------------------------------
            case 43 -> assertEncryptFindings(detectionStore, nodes, "AES");
            case 44 -> assertDecryptFindings(detectionStore, nodes, "AES");

            // -----------------------------------------------------------------
            // Section 10: combined usage patterns
            // -----------------------------------------------------------------
            case 45 -> {
                // TestAesCbcFullFlow: Mode=CBC, KeySize=256, Padding=PKCS7, CreateEncryptor
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("AES-256-CBC-PKCS7");
                assertThat(node.getChildren().get(KeyLength.class)).isNotNull();
                assertThat(node.getChildren().get(KeyLength.class).asString()).isEqualTo("256");
                assertThat(node.getChildren().get(com.ibm.mapper.model.Mode.class)).isNotNull();
                assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
            }
            case 46 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "AES-CBC-PKCS7");
            case 47 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "AES-CBC-PKCS7");
            case 48 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "AES-CFB-None");
            case 49 -> assertEncryptFindings(detectionStore, nodes, "AES");
            case 50 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "AES-ECB-None");
            case 51 -> assertEncryptFindings(detectionStore, nodes, "AES");
            case 52 -> assertEncryptFindings(detectionStore, nodes, "AES");

            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    // -------------------------------------------------------------------------
    // Assertion helpers
    // -------------------------------------------------------------------------

    private void assertModeFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes,
            @Nonnull String expectedMode,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> modeStore =
                getStoreOfValueType(Mode.class, store.getChildren());
        assertThat(modeStore).isNotNull();
        assertThat(modeStore.getDetectionValues()).hasSize(1);
        assertThat(modeStore.getDetectionValues().get(0).asString()).isEqualTo(expectedMode);

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
        assertThat(nodes.get(0).getChildren().get(com.ibm.mapper.model.Mode.class)).isNotNull();
    }

    private void assertKeySizeFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes,
            @Nonnull String expectedKeySize,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> keySizeStore =
                getStoreOfValueType(KeySize.class, store.getChildren());
        assertThat(keySizeStore).isNotNull();
        assertThat(keySizeStore.getDetectionValues()).hasSize(1);
        assertThat(keySizeStore.getDetectionValues().get(0).asString()).isEqualTo(expectedKeySize);

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
        assertThat(nodes.get(0).getChildren().get(KeyLength.class)).isNotNull();
        assertThat(nodes.get(0).getChildren().get(KeyLength.class).asString())
                .isEqualTo(expectedKeySize);
    }

    private void assertPaddingFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes,
            @Nonnull String expectedPadding,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> paddingStore =
                getStoreOfValueType(Padding.class, store.getChildren());
        assertThat(paddingStore).isNotNull();
        assertThat(paddingStore.getDetectionValues()).hasSize(1);
        assertThat(paddingStore.getDetectionValues().get(0).asString()).isEqualTo(expectedPadding);

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
    }

    private void assertEncryptFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> encryptStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(encryptStore).isNotNull();
        assertThat(encryptStore.getDetectionValues()).hasSize(1);
        assertThat(encryptStore.getDetectionValues().get(0).asString()).isEqualTo("ENCRYPT");

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
        assertThat(nodes.get(0).getChildren().get(Encrypt.class)).isNotNull();
    }

    private void assertDecryptFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes,
            @Nonnull String expectedNodeString) {

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> decryptStore =
                getStoreOfValueType(ValueAction.class, store.getChildren());
        assertThat(decryptStore).isNotNull();
        assertThat(decryptStore.getDetectionValues()).hasSize(1);
        assertThat(decryptStore.getDetectionValues().get(0).asString()).isEqualTo("DECRYPT");

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
        assertThat(nodes.get(0).getChildren().get(Decrypt.class)).isNotNull();
    }

    /**
     * Asserts mode+padding findings using the translated node tree. Direct-mode methods
     * (EncryptCbc, TryDecryptEcb, etc.) place Mode and Padding in the same child detection store,
     * so we validate via the final node string rather than per-store inspection.
     */
    private void assertModePaddingFindings(
            @Nonnull DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> store,
            @Nonnull List<INode> nodes,
            @Nonnull String expectedMode,
            @Nonnull String expectedPadding,
            @Nonnull String expectedNodeString) {

        // Verify that a Mode value with the expected string is detected somewhere in children
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> modeStore =
                getStoreOfValueType(Mode.class, store.getChildren());
        assertThat(modeStore).isNotNull();
        assertThat(modeStore.getDetectionValues())
                .anySatisfy(v -> assertThat(v.asString()).isEqualTo(expectedMode));

        // The translated node captures the combined result
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
    }
}
