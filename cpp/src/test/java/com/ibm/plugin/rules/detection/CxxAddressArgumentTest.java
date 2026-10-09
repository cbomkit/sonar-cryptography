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
package com.ibm.plugin.rules.detection;

import static com.ibm.plugin.ExpectedFinding.assertAllReported;
import static com.ibm.plugin.ExpectedFinding.assertFinding;
import static com.ibm.plugin.ExpectedFinding.finding;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CxxVerifier;
import com.ibm.plugin.ExpectedFinding;
import com.ibm.plugin.TestBase;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

/**
 * An argument {@code &v} passes the object {@code v}: a depending rule on that argument follows
 * {@code v} to the call that set it up, as it follows a variable passed as it is. Here {@code
 * AES_cbc_encrypt(in, out, len, &key, iv, enc)} is followed to the {@code AES_set_encrypt_key(k,
 * bits, &key)} of the same key, and reports the key size set there.
 */
class CxxAddressArgumentTest extends TestBase {

    private static final IDetectionRule<AstNode> KEY_SETUP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("AES_set_encrypt_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenSSL")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ENCRYPTION_WITH_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("AES_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-CBC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(KEY_SETUP))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "OpenSSL")
                    .withoutDependingDetectionRules();

    private static final List<ExpectedFinding> FINDINGS =
            List.of(
                    // 6: AES_cbc_encrypt(buf, buf, 64, &ak, iv, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CBC}[CipherContext{ValueAction:AES}"
                                    + "[CipherContext{KeySize:128}]]",
                            "BlockCipher:AES-128-CBC[BlockSize:128, KeyLength:128, Mode:CBC,"
                                    + " Oid:2.16.840.1.101.3.4.1.2]"),
                    // 14: AES_cbc_encrypt(buf, buf, 64, &k2, iv, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CBC}[CipherContext{ValueAction:AES}"
                                    + "[CipherContext{KeySize:256}]]",
                            "BlockCipher:AES-256-CBC[BlockSize:128, KeyLength:256, Mode:CBC,"
                                    + " Oid:2.16.840.1.101.3.4.1.42]"),
                    // 18: AES_cbc_encrypt(buf, buf, 64, key, iv, 1);
                    finding(
                            "CipherContext{ValueAction:AES-CBC}",
                            "BlockCipher:AES-CBC[BlockSize:128, Mode:CBC,"
                                    + " Oid:2.16.840.1.101.3.4.1]"));

    private int findings = 0;

    CxxAddressArgumentTest() {
        super(List.of(ENCRYPTION_WITH_KEY));
    }

    @Test
    void test() {
        CxxVerifier.verify("rules/detection/CxxAddressArgumentTestFile.cc", this);
        assertAllReported(FINDINGS, findings);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        findings++;
        assertFinding(FINDINGS, findingId, detectionStore, nodes);
    }
}
