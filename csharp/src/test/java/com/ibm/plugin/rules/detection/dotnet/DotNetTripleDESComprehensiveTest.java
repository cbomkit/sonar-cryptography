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
import com.ibm.engine.model.CipherAction;
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
 * Comprehensive test for all Triple DES (3DES)-related detection rules (DotNetTripleDES.java).
 *
 * <p>Covers all three TripleDES-related classes and their complete API surface:
 *
 * <ul>
 *   <li>TripleDES (abstract base)
 *   <li>TripleDESCryptoServiceProvider (derived from TripleDES, legacy CAPI)
 *   <li>TripleDESCng (derived from TripleDES, CNG-backed)
 * </ul>
 *
 * <p>TripleDES exposes no extra properties beyond those inherited from {@code SymmetricAlgorithm}
 * (unlike RC2's {@code EffectiveKeySize}), so the depending-rule set mirrors {@code DotNetDES}
 * exactly, plus a CNG-backed creation rule (mirroring {@code AesCng} in {@code DotNetAES}).
 *
 * <p>Finding mapping (one finding per test method in DotNetTripleDESComprehensiveTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–4):
 *   0  TestTripleDesCreate            → DESede
 *   1  TestTripleDesCreateNamed       → DESede
 *   2  TestTripleDesCsp               → DESede
 *   3  TestTripleDesCng               → DESede
 *   4  TestTripleDesCngNamed          → DESede
 *
 * Section 2 – property setters (findings 5–17):
 *   5  TestPropertyModeCBC            → DESede-CBC
 *   6  TestPropertyModeECB            → DESede-ECB
 *   7  TestPropertyModeCFB            → DESede-CFB
 *   8  TestPropertyModeOFB            → DESede-OFB
 *   9  TestPropertyModeCTS            → DESede-CTS
 *   10 TestPropertyKeySize            → DESede192 (KeyLength appended with no separator)
 *   11 TestPropertyPaddingPKCS7       → DESede-PKCS7
 *   12 TestPropertyPaddingNone        → DESede-None
 *   13 TestPropertyPaddingZeros       → DESede-Zeros
 *   14 TestPropertyPaddingANSIX923    → DESede-ANSIX923
 *   15 TestPropertyFeedbackSize       → DESede (BlockSize never rendered in asString)
 *   16 TestPropertyIV                 → DESede (no IV rule)
 *   17 TestPropertyKey                → DESede (no Key rule)
 *
 * Section 3 – CreateEncryptor/CreateDecryptor (findings 18–21):
 *   18 TestCreateEncryptorNoArgs      → DESede + Encrypt
 *   19 TestCreateEncryptorWithArgs    → DESede + Encrypt
 *   20 TestCreateDecryptorNoArgs      → DESede + Decrypt
 *   21 TestCreateDecryptorWithArgs    → DESede + Decrypt
 *
 * Section 4 – direct encrypt (findings 22–24):
 *   22 TestEncryptCbc                 → DESede-CBC-PKCS7
 *   23 TestEncryptEcb                 → DESede-ECB-None
 *   24 TestEncryptCfb                 → DESede-CFB-None
 *
 * Section 5 – direct decrypt (findings 25–27):
 *   25 TestDecryptCbc                 → DESede-CBC-PKCS7
 *   26 TestDecryptEcb                 → DESede-ECB-None
 *   27 TestDecryptCfb                 → DESede-CFB-None
 *
 * Section 6 – Try* variants (findings 28–33):
 *   28 TestTryEncryptCbc              → DESede-CBC-PKCS7
 *   29 TestTryDecryptCbc              → DESede-CBC-PKCS7
 *   30 TestTryEncryptEcb              → DESede-ECB-None
 *   31 TestTryDecryptEcb              → DESede-ECB-None
 *   32 TestTryEncryptCfb              → DESede-CFB-None
 *   33 TestTryDecryptCfb              → DESede-CFB-None
 *
 * Section 7 – key/IV generation (findings 34–35):
 *   34 TestGenerateKey                → DESede + KeyGeneration
 *   35 TestGenerateIV                 → DESede + Generate
 *
 * Section 8 – combined usage patterns (findings 36–42):
 *   36 TestTripleDesCbcFullFlow           → DESede-CBC-PKCS7 + Encrypt
 *   37 TestTripleDesCspEncryptCbc         → DESede-CBC-PKCS7
 *   38 TestTripleDesCspDecryptCbc         → DESede-CBC-PKCS7
 *   39 TestTripleDesCfbFeedback           → DESede-CFB-None
 *   40 TestTripleDesCbcWithEncryptorOverload → DESede + Encrypt
 *   41 TestTripleDesEcbEncrypt            → DESede-ECB-None
 *   42 TestTripleDesCngEncryptCbc         → DESede-CBC-PKCS7
 * </pre>
 *
 * <p>NOTE: unlike {@code RC2} (whose {@code asString()} uses {@code composeName(true, true, false)}
 * and never renders padding), {@code DESede.asString()} explicitly appends {@code KeyLength} (no
 * separator), then {@code -<Mode>}, then {@code -<Padding>} (see {@code DESede.java}). Verified
 * against actual test-run debug output ({@code target/node-tree.log}) rather than guessed.
 */
class DotNetTripleDESComprehensiveTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify(
                "rules/detection/dotnet/DotNetTripleDESComprehensiveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be TRIPLEDES
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("TRIPLEDES");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only DESede, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2, 3, 4 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("DESede");
            }

            // -----------------------------------------------------------------
            // Section 2a: property Mode setters
            // -----------------------------------------------------------------
            case 5 -> assertModeFindings(detectionStore, nodes, "CBC", "DESede-CBC");
            case 6 -> assertModeFindings(detectionStore, nodes, "ECB", "DESede-ECB");
            case 7 -> assertModeFindings(detectionStore, nodes, "CFB", "DESede-CFB");
            case 8 -> assertModeFindings(detectionStore, nodes, "OFB", "DESede-OFB");
            case 9 -> assertModeFindings(detectionStore, nodes, "CTS", "DESede-CTS");

            // -----------------------------------------------------------------
            // Section 2b: property KeySize setter — KeyLength is appended
            // directly after the name (no separator) by DESede.asString().
            // -----------------------------------------------------------------
            case 10 -> assertKeySizeFindings(detectionStore, nodes, "192", "DESede192");

            // -----------------------------------------------------------------
            // Section 2c: property Padding setters — unlike RC2, DESede.asString()
            // does render padding as a "-<Padding>" suffix.
            // -----------------------------------------------------------------
            case 11 -> assertPaddingFindings(detectionStore, nodes, "PKCS7", "DESede-PKCS7");
            case 12 -> assertPaddingFindings(detectionStore, nodes, "None", "DESede-None");
            case 13 -> assertPaddingFindings(detectionStore, nodes, "Zeros", "DESede-Zeros");
            case 14 -> assertPaddingFindings(detectionStore, nodes, "ANSIX923", "DESede-ANSIX923");

            // -----------------------------------------------------------------
            // Section 2d: FeedbackSize setter — BlockSize(8) detected but never
            // contributes to asString() (no BlockSize branch in DESede.asString())
            // -----------------------------------------------------------------
            case 15 -> {
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> fbStore =
                        getStoreOfValueType(
                                com.ibm.engine.model.BlockSize.class, detectionStore.getChildren());
                assertThat(fbStore).isNotNull();
                assertThat(fbStore.getDetectionValues()).hasSize(1);
                assertThat(fbStore.getDetectionValues().get(0).asString()).isEqualTo("8");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("DESede");
            }

            // -----------------------------------------------------------------
            // Section 2e: IV and Key setters — no detection rules for these
            // -----------------------------------------------------------------
            case 16, 17 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("DESede");
            }

            // -----------------------------------------------------------------
            // Section 3: CreateEncryptor / CreateDecryptor
            // -----------------------------------------------------------------
            case 18, 19 -> assertEncryptFindings(detectionStore, nodes, "DESede");
            case 20, 21 -> assertDecryptFindings(detectionStore, nodes, "DESede");

            // -----------------------------------------------------------------
            // Section 4: direct mode-specific encrypt
            // -----------------------------------------------------------------
            case 22 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "DESede-CBC-PKCS7");
            case 23 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "ECB", "None", "DESede-ECB-None");
            case 24 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CFB", "None", "DESede-CFB-None");

            // -----------------------------------------------------------------
            // Section 5: direct mode-specific decrypt
            // -----------------------------------------------------------------
            case 25 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "DESede-CBC-PKCS7");
            case 26 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "ECB", "None", "DESede-ECB-None");
            case 27 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CFB", "None", "DESede-CFB-None");

            // -----------------------------------------------------------------
            // Section 6: Try* variants
            // -----------------------------------------------------------------
            case 28, 29 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "DESede-CBC-PKCS7");
            case 30, 31 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "ECB", "None", "DESede-ECB-None");
            case 32, 33 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CFB", "None", "DESede-CFB-None");

            // -----------------------------------------------------------------
            // Section 7: GenerateKey / GenerateIV
            // -----------------------------------------------------------------
            case 34 -> {
                // tdes.GenerateKey() → KeyGeneration functionality node
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
            case 35 -> {
                // tdes.GenerateIV() → Generate functionality node
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
            // Section 8: combined usage patterns
            // -----------------------------------------------------------------
            case 36 -> {
                // TestTripleDesCbcFullFlow: Mode=CBC, Padding=PKCS7, CreateEncryptor
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("DESede-CBC-PKCS7");
                assertThat(node.getChildren().get(com.ibm.mapper.model.Mode.class)).isNotNull();
                assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
            }
            case 37 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "DESede-CBC-PKCS7");
            case 38 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "DESede-CBC-PKCS7");
            case 39 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CFB", "None", "DESede-CFB-None");
            case 40 -> assertEncryptFindings(detectionStore, nodes, "DESede");
            case 41 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "ECB", "None", "DESede-ECB-None");
            case 42 ->
                    assertModePaddingFindings(
                            detectionStore, nodes, "CBC", "PKCS7", "DESede-CBC-PKCS7");

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
                getStoreOfValueType(CipherAction.class, store.getChildren());
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
                getStoreOfValueType(CipherAction.class, store.getChildren());
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

        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> modeStore =
                getStoreOfValueType(Mode.class, store.getChildren());
        assertThat(modeStore).isNotNull();
        assertThat(modeStore.getDetectionValues())
                .anySatisfy(v -> assertThat(v.asString()).isEqualTo(expectedMode));

        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
        assertThat(nodes.get(0).asString()).isEqualTo(expectedNodeString);
    }
}
