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
 * Comprehensive test for all RC2-related detection rules (DotNetRC2.java).
 *
 * <p>Covers both RC2-related classes and their complete API surface:
 *
 * <ul>
 *   <li>RC2 (abstract base)
 *   <li>RC2CryptoServiceProvider (derived from RC2)
 * </ul>
 *
 * <p>Like DES, RC2 has no CNG-backed subclass and no AEAD variant, so there is no equivalent to
 * Section 8/9 of DotNetAESComprehensiveTest (AesGcm/AesCcm). Unlike DES, RC2 additionally exposes
 * an {@code EffectiveKeySize} property, which is reused as a {@code KeySize} detection (see
 * DotNetRC2.java) and is covered by an extra test method in Section 2 (property setters).
 *
 * <p>Finding mapping (one finding per test method in DotNetRC2ComprehensiveTestFile.cs):
 *
 * <pre>
 * Section 1 – factory methods / constructors (findings 0–2):
 *   0  TestRc2Create                  → RC2
 *   1  TestRc2CreateNamed             → RC2
 *   2  TestRc2Csp                     → RC2
 *
 * Section 2 – property setters (findings 3–16):
 *   3  TestPropertyModeCBC            → RC2-CBC
 *   4  TestPropertyModeECB            → RC2-ECB
 *   5  TestPropertyModeCFB            → RC2-CFB
 *   6  TestPropertyModeOFB            → RC2-OFB
 *   7  TestPropertyModeCTS            → RC2-CTS
 *   8  TestPropertyKeySize            → RC2-128
 *   9  TestPropertyEffectiveKeySize   → RC2-64 (reused as KeySize, see DotNetRC2.java)
 *   10 TestPropertyPaddingPKCS7       → RC2 (padding never rendered in asString)
 *   11 TestPropertyPaddingNone        → RC2 (padding never rendered in asString)
 *   12 TestPropertyPaddingZeros       → RC2 (padding never rendered in asString)
 *   13 TestPropertyPaddingANSIX923    → RC2 (padding never rendered in asString)
 *   14 TestPropertyFeedbackSize       → RC2 (BlockSize never rendered in asString)
 *   15 TestPropertyIV                 → RC2 (no IV rule)
 *   16 TestPropertyKey                → RC2 (no Key rule)
 *
 * Section 3 – CreateEncryptor/CreateDecryptor (findings 17–20):
 *   17 TestCreateEncryptorNoArgs      → RC2 + Encrypt
 *   18 TestCreateEncryptorWithArgs    → RC2 + Encrypt
 *   19 TestCreateDecryptorNoArgs      → RC2 + Decrypt
 *   20 TestCreateDecryptorWithArgs    → RC2 + Decrypt
 *
 * Section 4 – direct encrypt (findings 21–23):
 *   21 TestEncryptCbc                 → RC2-CBC
 *   22 TestEncryptEcb                 → RC2-ECB
 *   23 TestEncryptCfb                 → RC2-CFB
 *
 * Section 5 – direct decrypt (findings 24–26):
 *   24 TestDecryptCbc                 → RC2-CBC
 *   25 TestDecryptEcb                 → RC2-ECB
 *   26 TestDecryptCfb                 → RC2-CFB
 *
 * Section 6 – Try* variants (findings 27–32):
 *   27 TestTryEncryptCbc              → RC2-CBC
 *   28 TestTryDecryptCbc              → RC2-CBC
 *   29 TestTryEncryptEcb              → RC2-ECB
 *   30 TestTryDecryptEcb              → RC2-ECB
 *   31 TestTryEncryptCfb              → RC2-CFB
 *   32 TestTryDecryptCfb              → RC2-CFB
 *
 * Section 7 – key/IV generation (findings 33–34):
 *   33 TestGenerateKey                → RC2 + KeyGeneration
 *   34 TestGenerateIV                 → RC2 + Generate
 *
 * Section 8 – combined usage patterns (findings 35–41):
 *   35 TestRc2CbcFullFlow             → RC2-CBC + Encrypt
 *   36 TestRc2CspEncryptCbc           → RC2-CBC
 *   37 TestRc2CspDecryptCbc           → RC2-CBC
 *   38 TestRc2CfbFeedback             → RC2-CFB
 *   39 TestRc2CbcWithEncryptorOverload → RC2 + Encrypt
 *   40 TestRc2EcbEncrypt              → RC2-ECB
 *   41 TestRc2CspEffectiveKeySize     → RC2-40
 * </pre>
 *
 * <p>NOTE: unlike DES, {@code RC2}'s abstract-base constructor {@code RC2(DetectionLocation)} does
 * <em>not</em> seed a default {@code KeyLength} or {@code BlockSize} (see {@code RC2.java}) —
 * {@code RC2.asString()} uses {@code composeName(true, true, false)} just like {@code DES}, but
 * with nothing to render unless a KeySize/EffectiveKeySize/Mode is actually detected. So the plain
 * "RC2" string appears whenever no such property was set, and Padding never contributes to the
 * string even when a Padding value is detected as a child. Verified against actual test-run debug
 * output ({@code target/node-tree.log}) rather than guessed.
 */
class DotNetRC2ComprehensiveTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetRC2ComprehensiveTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {

        // Every top-level finding must be RC2
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<CSharpTree> primary = detectionStore.getDetectionValues().get(0);
        assertThat(primary).isInstanceOf(ValueAction.class);
        assertThat(primary.asString()).isEqualTo("RC2");

        switch (findingId) {

            // -----------------------------------------------------------------
            // Section 1: simple constructors — only RC2, no children fired
            // -----------------------------------------------------------------
            case 0, 1, 2 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("RC2");
            }

            // -----------------------------------------------------------------
            // Section 2a: property Mode setters
            // -----------------------------------------------------------------
            case 3 -> assertModeFindings(detectionStore, nodes, "CBC", "RC2-CBC");
            case 4 -> assertModeFindings(detectionStore, nodes, "ECB", "RC2-ECB");
            case 5 -> assertModeFindings(detectionStore, nodes, "CFB", "RC2-CFB");
            case 6 -> assertModeFindings(detectionStore, nodes, "OFB", "RC2-OFB");
            case 7 -> assertModeFindings(detectionStore, nodes, "CTS", "RC2-CTS");

            // -----------------------------------------------------------------
            // Section 2b: property KeySize / EffectiveKeySize setters — both
            // reuse KeySizeFactory (see DotNetRC2.java), so both render as
            // -<value> in the node string via composeName's KeyLength branch.
            // -----------------------------------------------------------------
            case 8 -> assertKeySizeFindings(detectionStore, nodes, "128", "RC2-128");
            case 9 -> assertKeySizeFindings(detectionStore, nodes, "64", "RC2-64");

            // -----------------------------------------------------------------
            // Section 2c: property Padding setters — Padding is tracked as a
            // child node but RC2.asString() uses composeName(true, true, false),
            // so padding never contributes to the rendered string.
            // -----------------------------------------------------------------
            case 10 -> assertPaddingFindings(detectionStore, nodes, "PKCS7", "RC2");
            case 11 -> assertPaddingFindings(detectionStore, nodes, "None", "RC2");
            case 12 -> assertPaddingFindings(detectionStore, nodes, "Zeros", "RC2");
            case 13 -> assertPaddingFindings(detectionStore, nodes, "ANSIX923", "RC2");

            // -----------------------------------------------------------------
            // Section 2d: FeedbackSize setter — BlockSize(8) detected but never
            // contributes to asString() (composeName has no BlockSize branch)
            // -----------------------------------------------------------------
            case 14 -> {
                DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> fbStore =
                        getStoreOfValueType(BlockSize.class, detectionStore.getChildren());
                assertThat(fbStore).isNotNull();
                assertThat(fbStore.getDetectionValues()).hasSize(1);
                assertThat(fbStore.getDetectionValues().get(0).asString()).isEqualTo("8");
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("RC2");
            }

            // -----------------------------------------------------------------
            // Section 2e: IV and Key setters — no detection rules for these
            // -----------------------------------------------------------------
            case 15, 16 -> {
                assertThat(nodes).hasSize(1);
                assertThat(nodes.get(0).getKind()).isEqualTo(BlockCipher.class);
                assertThat(nodes.get(0).asString()).isEqualTo("RC2");
            }

            // -----------------------------------------------------------------
            // Section 3: CreateEncryptor / CreateDecryptor
            // -----------------------------------------------------------------
            case 17, 18 -> assertEncryptFindings(detectionStore, nodes, "RC2");
            case 19, 20 -> assertDecryptFindings(detectionStore, nodes, "RC2");

            // -----------------------------------------------------------------
            // Section 4: direct mode-specific encrypt
            // -----------------------------------------------------------------
            case 21 -> assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "RC2-CBC");
            case 22 -> assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "RC2-ECB");
            case 23 -> assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "RC2-CFB");

            // -----------------------------------------------------------------
            // Section 5: direct mode-specific decrypt
            // -----------------------------------------------------------------
            case 24 -> assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "RC2-CBC");
            case 25 -> assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "RC2-ECB");
            case 26 -> assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "RC2-CFB");

            // -----------------------------------------------------------------
            // Section 6: Try* variants
            // -----------------------------------------------------------------
            case 27, 28 ->
                    assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "RC2-CBC");
            case 29, 30 ->
                    assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "RC2-ECB");
            case 31, 32 ->
                    assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "RC2-CFB");

            // -----------------------------------------------------------------
            // Section 7: GenerateKey / GenerateIV
            // -----------------------------------------------------------------
            case 33 -> {
                // rc2.GenerateKey() → KeyGeneration functionality node
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
            case 34 -> {
                // rc2.GenerateIV() → Generate functionality node
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
            case 35 -> {
                // TestRc2CbcFullFlow: Mode=CBC, Padding=PKCS7 (unrendered), CreateEncryptor
                assertThat(nodes).hasSize(1);
                INode node = nodes.get(0);
                assertThat(node.getKind()).isEqualTo(BlockCipher.class);
                assertThat(node.asString()).isEqualTo("RC2-CBC");
                assertThat(node.getChildren().get(com.ibm.mapper.model.Mode.class)).isNotNull();
                assertThat(node.getChildren().get(Encrypt.class)).isNotNull();
            }
            case 36 -> assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "RC2-CBC");
            case 37 -> assertModePaddingFindings(detectionStore, nodes, "CBC", "PKCS7", "RC2-CBC");
            case 38 -> assertModePaddingFindings(detectionStore, nodes, "CFB", "None", "RC2-CFB");
            case 39 -> assertEncryptFindings(detectionStore, nodes, "RC2");
            case 40 -> assertModePaddingFindings(detectionStore, nodes, "ECB", "None", "RC2-ECB");
            case 41 -> assertKeySizeFindings(detectionStore, nodes, "40", "RC2-40");

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
