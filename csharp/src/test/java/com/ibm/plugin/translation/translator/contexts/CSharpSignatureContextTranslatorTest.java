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

import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class CSharpSignatureContextTranslatorTest {

    @Test
    void testRSA() {
        CSharpSignatureContextTranslator translator = new CSharpSignatureContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("RSA");
        SignatureContext context = new SignatureContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(RSA.class);
        assertThat(node.asString()).isEqualTo("RSA");
    }

    @Test
    void testECDSA() {
        CSharpSignatureContextTranslator translator = new CSharpSignatureContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("ECDSA");
        SignatureContext context = new SignatureContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(ECDSA.class);
        assertThat(node.asString()).isEqualTo("ECDSA");
    }

    @Test
    void testDSA() {
        CSharpSignatureContextTranslator translator = new CSharpSignatureContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("DSA");
        SignatureContext context = new SignatureContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(DSA.class);
        assertThat(node.asString()).isEqualTo("DSA");
    }

    @Test
    void testSignAction() {
        CSharpSignatureContextTranslator translator = new CSharpSignatureContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        SignatureAction<?> value = new SignatureAction<>(SignatureAction.Action.SIGN);
        SignatureContext context = new SignatureContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(Signature.class);
        assertThat(node.getKind()).isEqualTo(Sign.class);
    }

    @Test
    void testVerifyAction() {
        CSharpSignatureContextTranslator translator = new CSharpSignatureContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        SignatureAction<?> value = new SignatureAction<>(SignatureAction.Action.VERIFY);
        SignatureContext context = new SignatureContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(Verify.class);
    }

    @Test
    void testUnknownValue() {
        CSharpSignatureContextTranslator translator = new CSharpSignatureContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("UNKNOWN");
        SignatureContext context = new SignatureContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isEmpty();
    }
}
