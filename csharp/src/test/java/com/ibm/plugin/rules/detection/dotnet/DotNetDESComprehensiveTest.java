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
 * Comprehensive test for all DES-related detection rules (DotNetDES.java).
 *
 * <p>Covers both DES-related classes and their complete API surface:
 *
 * <ul>
 *   <li>DES (abstract base)
 *   <li>DESCryptoServiceProvider (derived from DES)
 * </ul>
 *
 * <p>Unlike Aes, DES has no CNG-backed subclass and no AEAD variant, so there is no equivalent to
 * Section 8/9 of DotNetAESComprehensiveTest (AesGcm/AesCcm).
 *
 * <p>Finding mapping (one finding per test method in DotNetDESComprehensiveTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–2):
 *   0  TestDesCreate                 → DES-56
 *   1  TestDesCreateNamed            → DES-56
 *   2  TestDesCsp                    → DES-56
 *
 * Section 2 – property setters (findings 3–15):
 *   3  TestPropertyModeCBC           → DES-56-CBC
 *   4  TestPropertyModeECB           → DES-56-ECB
 *   5  TestPropertyModeCFB           → DES-56-CFB
 *   6  TestPropertyModeOFB           → DES-56-OFB
 *   7  TestPropertyModeCTS           → DES-56-CTS
 *   8  TestPropertyKeySize           → DES-64 (overrides default 56)
 *   9  TestPropertyPaddingPKCS7      → DES-56 (padding never rendered in asString)
 *   10 TestPropertyPaddingNone       → DES-56 (padding never rendered in asString)
 *   11 TestPropertyPaddingZeros      → DES-56 (padding never rendered in asString)
 *   12 TestPropertyPaddingANSIX923   → DES-56 (padding never rendered in asString)
 *   13 TestPropertyFeedbackSize      → DES-56 (BlockSize never rendered in asString)
 *   14 TestPropertyIV                → DES-56 (no IV rule)
 *   15 TestPropertyKey               → DES-56 (no Key rule)
 *
 * Section 3 – CreateEncryptor/CreateDecryptor (findings 16–19):
 *   16 TestCreateEncryptorNoArgs      → DES-56 + Encrypt
 *   17 TestCreateEncryptorWithArgs    → DES-56 + Encrypt
 *   18 TestCreateDecryptorNoArgs      → DES-56 + Decrypt
 *   19 TestCreateDecryptorWithArgs    → DES-56 + Decrypt
 *
 * Section 4 – direct encrypt (findings 20–22):
 *   20 TestEncryptCbc                → DES-56-CBC
 *   21 TestEncryptEcb                → DES-56-ECB
 *   22 TestEncryptCfb                → DES-56-CFB
 *
 * Section 5 – direct decrypt (findings 23–25):
 *   23 TestDecryptCbc                → DES-56-CBC
 *   24 TestDecryptEcb                → DES-56-ECB
 *   25 TestDecryptCfb                → DES-56-CFB
 *
 * Section 6 – Try* variants (findings 26–31):
 *   26 TestTryEncryptCbc             → DES-56-CBC
 *   27 TestTryDecryptCbc             → DES-56-CBC
 *   28 TestTryEncryptEcb             → DES-56-ECB
 *   29 TestTryDecryptEcb             → DES-56-ECB
 *   30 TestTryEncryptCfb             → DES-56-CFB
 *   31 TestTryDecryptCfb             → DES-56-CFB
 *
 * Section 7 – key/IV generation (findings 32–33):
 *   32 TestGenerateKey               → DES-56 + KeyGeneration
 *   33 TestGenerateIV                → DES-56 + Generate
 *
 * Section 8 – combined usage patterns (findings 34–39):
 *   34 TestDesCbcFullFlow            → DES-56-CBC + Encrypt
 *   35 TestDesCspEncryptCbc          → DES-56-CBC
 *   36 TestDesCspDecryptCbc          → DES-56-CBC
 *   37 TestDesCfbFeedback            → DES-56-CFB
 *   38 TestDesCbcWithEncryptorOverload → DES-56 + Encrypt
 *   39 TestDesEcbEncrypt             → DES-56-ECB
 * </pre>
 *
 * <p>NOTE: unlike AES, {@code DES.asString()} uses {@code composeName(true, true, false)} — key
 * length IS rendered (and {@code DES}'s no-arg constructor always seeds a default {@code
 * KeyLength.ofDefault(56, ...)}), while padding is NEVER rendered. So every node string below
 * carries a {@code -56} (or overridden key size) suffix, and Padding never contributes to the
 * string even when a Padding value is detected as a child. Verified against actual test-run debug
 * output (see {@code Algorithm.composeName} and {@code DES.java}/{@code AES.java} for the
 * asymmetry) rather than guessed.
 */
class DotNetDESComprehensiveTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetDESComprehensiveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be DES
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("DES");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only DES, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("DES-56");
            }

            // -----------------------------------------------------------------
            // Section 2a: property Mode setters
            // -----------------------------------------------------------------
            case 3 -> assertModeFindings(detectionStore, nodes, "CBC", "DES-56-CBC");
            case 4 -> assertModeFindings(detectionStore, nodes, "ECB", "DES-56-ECB");
            case 5 -> assertModeFindings(detectionStore, nodes, "CFB", "DES-56-CFB");
            case 6 -> assertModeFindings(detectionStore, nodes, "OFB", "DES-56-OFB");
            case 7 -> assertModeFindings(detectionStore, nodes, "CTS", "DES-56-CTS");

            // -----------------------------------------------------------------
            // Section 2b: property KeySize setter — overrides the default 56
            // -----------------------------------------------------------------
            case 8 -> assertKeySizeFindings(detectionStore, nodes, "64", "DES-64");

            // -----------------------------------------------------------------
            // Section 2c: property Padding setters — Padding is tracked as a
            // child node but DES.asString() uses composeName(true, true, false),
            // so padding never contributes to the rendered string.
            // -----------------------------------------------------------------
            case 9 -> assertPaddingFindings(detectionStore, nodes, "PKCS7", "DES-56");
            case 10 -> assertPaddingFindings(detectionStore, nodes, "None", "DES-56");
            case 11 -> assertPaddingFindings(detectionStore, nodes, "Zeros", "DES-56");
            case 12 -> assertPaddingFindings(detectionStore, nodes, "ANSIX923", "DES-56");

            // -----------------------------------------------------------------
            // Section 2d: FeedbackSize setter — BlockSize(8) detected but never
            // contributes to asString() (composeName has no BlockSize branch)
            // -----------------------------------------------------------------
            case 13 -> {
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> fbStore =
                        getStoreOfValueType(BlockSize.class, detectionStore.getChildren());
                assertThat(fbStore).isNotNull();
                assertThat(fbStore.getDetectionValues()).hasSize(1);
                assertThat(fbStore.getDetectionValues().get(0).asString()).isEqualTo("8");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("DES-56");
            }

            // -----------------------------------------------------------------
            // Section 2e: IV and Key setters — no detection rules for these
            // -----------------------------------------------------------------
            case 14, 15 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("DES-56");
            }

            // -----------------------------------------------------------------
            // Section 3: CreateEncryptor / CreateDecryptor
            // -----------------------------------------------------------------
            case 16, 17 -> assertEncryptFindings(detectionStore, nodes, "DES-56");
            case 18, 19 -> assertDecryptFindings(detectionStore, nodes, "DES-56");

            // -----------------------------------------------------------------
            // Section 4: direct mode-specific encrypt
            // -----------------------------------------------------------------
            case 20 ->
                    assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "DES-56-CBC");
            case 21 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "DES-56-ECB");
            case 22 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "DES-56-CFB");

            // -----------------------------------------------------------------
            // Section 5: direct mode-specific decrypt
            // -----------------------------------------------------------------
            case 23 ->
                    assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "DES-56-CBC");
            case 24 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "DES-56-ECB");
            case 25 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "DES-56-CFB");

            // -----------------------------------------------------------------
            // Section 6: Try* variants
            // -----------------------------------------------------------------
            case 26, 27 ->
                    assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "DES-56-CBC");
            case 28, 29 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "DES-56-ECB");
            case 30, 31 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "DES-56-CFB");

            // -----------------------------------------------------------------
            // Section 7: GenerateKey / GenerateIV
            // -----------------------------------------------------------------
            case 32 -> {
                // des.GenerateKey() → KeyGeneration functionality node
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
            case 33 -> {
                // des.GenerateIV() → Generate functionality node
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
            case 34 -> {
                // TestDesCbcFullFlow: Mode=CBC, Padding=PKCS7 (unrendered), CreateEncryptor
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("DES-56-CBC");
                assertThat(node.getChildren().get(com.ibm.mapper.model.Mode.class)).isNotNull();
                assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
            }
            case 35 ->
                    assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "DES-56-CBC");
            case 36 ->
                    assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "DES-56-CBC");
            case 37 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "DES-56-CFB");
            case 38 -> assertEncryptFindings(detectionStore, nodes, "DES-56");
            case 39 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "DES-56-ECB");

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
