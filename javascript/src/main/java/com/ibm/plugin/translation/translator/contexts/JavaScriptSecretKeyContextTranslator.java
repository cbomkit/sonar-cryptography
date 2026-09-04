/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 IBM
 */
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class JavaScriptSecretKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            return switch (algorithm.asString().toLowerCase().trim()) {
                case "aes" -> Optional.of(new SecretKey(new AES(detectionLocation)));
                default -> Optional.empty();
            };
        } else if (value instanceof KeyAction<Tree>) {
            return Optional.of(new Generate(detectionLocation));
        }
        return Optional.empty();
    }
}
