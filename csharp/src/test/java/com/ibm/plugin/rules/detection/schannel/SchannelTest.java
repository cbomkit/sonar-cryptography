/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.schannel;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * What direct Schannel P/Invoke states, and -- mostly -- what it does not.
 *
 * <p>The counter-checks are the greater part of this fixture, because the two field rules match on
 * an {@code ANY} receiver and the Win32 field name is their only guard. The deny-list fields are
 * asserted absent on purpose: {@code grbitDisabledProtocols} and every {@code CRYPTO_SETTINGS}
 * field describe cryptography being switched off, and reporting them would state the opposite of
 * what the source says.
 */
class SchannelTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/schannel/SchannelTestFile.cs", this);
        assertThat(found)
                .as("every protocol direct Schannel P/Invoke states, and nothing it does not")
                .containsExactly(
                        // AcquireCredentialsHandle, once per Schannel package spelling: a member
                        // access to UNISP_NAME, the literal "Schannel", a local string constant
                        // that resolves through to the documented package string, and a member
                        // access to SCHANNEL_NAME. No version: the call names a package, not a
                        // version.
                        "Zeile 117  TLS=TLS",
                        "Zeile 134  TLS=TLS",
                        "Zeile 152  TLS=TLS",
                        // The same call with inline `out long credential` declarations. Worth
                        // asserting: an argument whose value cannot be converted keeps its
                        // position, so the nine-argument arity the rule requires still holds.
                        "Zeile 167  TLS=TLS",
                        // An object initializer. The initializer's setters are emitted before the
                        // creation statement they belong to, which is why 185 precedes 182. The
                        // dwMinimumCipherStrength and dwMaximumCipherStrength written on the next
                        // two lines contribute nothing -- they are a policy floor and ceiling on
                        // bulk cipher key length and name no algorithm to attach a length to.
                        "Zeile 185  TLS=TLSv1.2[Version=1.2]",
                        "Zeile 182  TLS=TLS",
                        // A flags combination is a set, not a number: both versions are offered.
                        "Zeile 194  TLS=TLS",
                        "Zeile 195  TLS=TLSv1.2[Version=1.2]",
                        "Zeile 195  TLS=TLSv1.3[Version=1.3]",
                        // The server-side flags and the server|client alias name the same versions
                        // as their client-side twins. The direction is a property of the endpoint,
                        // not of the cryptography.
                        "Zeile 202  TLS=TLS",
                        "Zeile 203  TLS=TLSv1.2[Version=1.2]",
                        "Zeile 204  TLS=TLSv1.3[Version=1.3]",
                        "Zeile 205  TLS=TLSv1.2[Version=1.2]",
                        // TLS 1.1, then the three spellings of the TLS 1.0 flag: SP_PROT_TLS1_0_*
                        // is an alias of SP_PROT_TLS1_*, and both have to read the same.
                        "Zeile 211  TLS=TLS",
                        "Zeile 212  TLS=TLSv1.1[Version=1.1]",
                        "Zeile 213  TLS=TLSv1.0[Version=1.0]",
                        "Zeile 214  TLS=TLSv1.0[Version=1.0]",
                        "Zeile 215  TLS=TLSv1.0[Version=1.0]",
                        // SSL keeps its own name rather than becoming a nameless TLS, so a reader
                        // sees what was actually offered.
                        "Zeile 221  TLS=TLS",
                        "Zeile 222  Protocol=SSLv3",
                        "Zeile 223  Protocol=SSLv3",
                        "Zeile 224  Protocol=SSLv2",
                        // DTLS likewise. SP_PROT_DTLS_CLIENT is an alias of DTLS 1.0 in the
                        // header, but the name does not say so, so it reports a bare DTLS.
                        "Zeile 230  TLS=TLS",
                        "Zeile 231  Protocol=DTLSv1.2",
                        "Zeile 232  Protocol=DTLSv1.0",
                        "Zeile 233  Protocol=DTLS",
                        // SP_PROT_NONE is zero, which the documentation defines as "Schannel
                        // selects the protocol": TLS without a version is the whole of what is
                        // known, exactly as for SslProtocols.None.
                        "Zeile 239  TLS=TLS",
                        "Zeile 240  TLS=TLS",
                        // The modern credential structure. It has no enabled-protocol field at
                        // all, so the creation is the entire statement it makes.
                        "Zeile 246  TLS=TLS",
                        // Everything from here on is a counter-check, and each contributes only
                        // the bare TLS of the `new SCHANNEL_CRED()` on its first line -- a
                        // credential structure really is a Schannel credential. What is absent is
                        // the version: an unqualified constant that resolves to a number (294), a
                        // numeric literal (301), a method parameter (308), the obsolete PCT flag
                        // and a whole-range mask (315, 316), and a name that is no flag of this
                        // field (323). The cipher-strength pair at 333/334 adds nothing either.
                        "Zeile 293  TLS=TLS",
                        "Zeile 300  TLS=TLS",
                        "Zeile 307  TLS=TLS",
                        "Zeile 314  TLS=TLS",
                        "Zeile 322  TLS=TLS",
                        "Zeile 332  TLS=TLS");
        // containsExactly is exhaustive, so the following are asserted absent by its very
        // completeness -- they are the point of the fixture's second half:
        //   - TLS_PARAMETERS.grbitDisabledProtocols (262, 264) -- the same flag vocabulary with
        //     the opposite meaning, plus the TLS_PARAMETERS creation that carries it.
        //   - every CRYPTO_SETTINGS field (275-283) -- eAlgorithmUsage, cChainingModes,
        //     dwMinBitLength, dwMaxBitLength. The structure is documented as "disabled
        //     cryptographic settings"; an algorithm being switched off is not one in use.
        //   - EnabledProtocols / GrbitEnabledProtocols on an unrelated type (343, 344) -- the
        //     exact Win32 field name is the guard, and nothing weaker matches.
        //   - an unrelated nine-less AcquireCredentialsHandle (353).
        //   - the "Negotiate" package (361) and a package name taken from a parameter (378).
    }

    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream().map(SchannelTest::render).sorted().toList();
        return children.isEmpty() ? self : self + children;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        // A detection whose value the translator declines -- a deny-list field, an unknown flag
        // name, a package that is not Schannel -- arrives here with no nodes at all.
        nodes.forEach(
                node ->
                        found.add(
                                (node instanceof com.ibm.mapper.model.Protocol p
                                                ? "Zeile " + p.getDetectionContext().lineNumber()
                                                : "Zeile ?")
                                        + "  "
                                        + render(node)));
    }
}
