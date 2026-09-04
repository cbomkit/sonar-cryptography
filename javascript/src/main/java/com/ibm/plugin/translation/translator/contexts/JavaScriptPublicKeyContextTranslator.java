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
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.api.Tree;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class JavaScriptPublicKeyContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree>) {
            PublicKeyEncryption rsa = new RSA(PublicKeyEncryption.class, detectionLocation);
            PublicKey publicKey = new PublicKey(rsa);
            publicKey.put(new KeyGeneration(detectionLocation));
            return Optional.of(publicKey);
        } else if (value instanceof KeyAction<Tree>) {
            return Optional.of(new Generate(detectionLocation));
        }
        return Optional.empty();
    }
}
