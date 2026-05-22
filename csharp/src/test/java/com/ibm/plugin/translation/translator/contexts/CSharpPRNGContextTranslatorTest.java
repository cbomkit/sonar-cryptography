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

import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

class CSharpPRNGContextTranslatorTest {

    @Test
    void testRandomNumberGenerator() {
        CSharpPRNGContextTranslator translator = new CSharpPRNGContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("RandomNumberGenerator");
        PRNGContext context = new PRNGContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
    }

    @Test
    void testRNGCryptoServiceProvider() {
        CSharpPRNGContextTranslator translator = new CSharpPRNGContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("RNGCryptoServiceProvider");
        PRNGContext context = new PRNGContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
    }

    @Test
    void testRandom() {
        CSharpPRNGContextTranslator translator = new CSharpPRNGContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("Random");
        PRNGContext context = new PRNGContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isPresent();
        INode node = result.get();
        assertThat(node.getKind()).isEqualTo(PseudorandomNumberGenerator.class);
    }

    @Test
    void testUnknownValue() {
        CSharpPRNGContextTranslator translator = new CSharpPRNGContextTranslator();
        DetectionLocation location = new DetectionLocation("test.cs", 1, 0, java.util.List.of(), new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "test"; }
        });

        ValueAction<?> value = new ValueAction<>("UnknownCrypto");
        PRNGContext context = new PRNGContext();

        Optional<INode> result = translator.translate(new IDetectionRule() {
            @Nonnull @Override public String getIdentifier() { return "DotNet"; }
        }, value, context, location);

        assertThat(result).isEmpty();
    }
}
