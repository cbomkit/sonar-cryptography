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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.language.cxx.CxxSemantic;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.model.factory.InitializationVectorSizeFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.TagSizeFactory;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * Resolves the cipher parameter set by {@code EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr)}. The
 * factory is applied to {@code arg}; the command {@code type} of the same call selects what {@code
 * arg} is: the key length ({@code EVP_CTRL_SET_KEY_LENGTH}, in bytes), the effective key bits of
 * RC2 ({@code EVP_CTRL_SET_RC2_KEY_BITS}), the IV length ({@code EVP_CTRL_AEAD_SET_IVLEN} and its
 * GCM and CCM names, in bytes) or the tag length ({@code EVP_CTRL_AEAD_SET_TAG} / {@code
 * EVP_CTRL_AEAD_GET_TAG} and their GCM and CCM names, in bytes). Other commands resolve to nothing.
 */
public final class OpenSSLCipherCtrlFactory implements IValueFactory<AstNode> {

    private static final int TYPE_ARGUMENT = 1;

    private enum Parameter {
        KEY_LENGTH,
        RC2_KEY_BITS,
        IV_LENGTH,
        TAG_LENGTH
    }

    /** The {@code EVP_CTRL_*} commands (evp.h), by name and by value. */
    private static final Map<Object, Parameter> COMMANDS =
            Map.ofEntries(
                    Map.entry("EVP_CTRL_SET_KEY_LENGTH", Parameter.KEY_LENGTH),
                    Map.entry(0x1, Parameter.KEY_LENGTH),
                    Map.entry("EVP_CTRL_SET_RC2_KEY_BITS", Parameter.RC2_KEY_BITS),
                    Map.entry(0x3, Parameter.RC2_KEY_BITS),
                    Map.entry("EVP_CTRL_AEAD_SET_IVLEN", Parameter.IV_LENGTH),
                    Map.entry("EVP_CTRL_GCM_SET_IVLEN", Parameter.IV_LENGTH),
                    Map.entry("EVP_CTRL_CCM_SET_IVLEN", Parameter.IV_LENGTH),
                    Map.entry(0x9, Parameter.IV_LENGTH),
                    Map.entry("EVP_CTRL_AEAD_GET_TAG", Parameter.TAG_LENGTH),
                    Map.entry("EVP_CTRL_GCM_GET_TAG", Parameter.TAG_LENGTH),
                    Map.entry("EVP_CTRL_CCM_GET_TAG", Parameter.TAG_LENGTH),
                    Map.entry(0x10, Parameter.TAG_LENGTH),
                    Map.entry("EVP_CTRL_AEAD_SET_TAG", Parameter.TAG_LENGTH),
                    Map.entry("EVP_CTRL_GCM_SET_TAG", Parameter.TAG_LENGTH),
                    Map.entry("EVP_CTRL_CCM_SET_TAG", Parameter.TAG_LENGTH),
                    Map.entry(0x11, Parameter.TAG_LENGTH));

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        final AstNode call = enclosingCall(resolvedValue.tree());
        if (call == null) {
            return Optional.empty();
        }
        final List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(call);
        if (arguments.size() <= TYPE_ARGUMENT) {
            return Optional.empty();
        }
        for (ResolvedValue<Object, AstNode> type :
                CxxSemantic.resolveValues(
                        Object.class,
                        arguments.get(TYPE_ARGUMENT),
                        new LinkedList<>(),
                        null,
                        false,
                        null)) {
            final Parameter parameter = COMMANDS.get(type.value());
            if (parameter != null) {
                return factoryOf(parameter).apply(resolvedValue);
            }
        }
        return Optional.empty();
    }

    @Nonnull
    private static IValueFactory<AstNode> factoryOf(@Nonnull Parameter parameter) {
        return switch (parameter) {
            case KEY_LENGTH -> new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BYTE));
            case RC2_KEY_BITS -> new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BIT));
            case IV_LENGTH ->
                    new OpenSSLSizeFactory(
                            new InitializationVectorSizeFactory<>(Size.UnitType.BYTE));
            case TAG_LENGTH -> new OpenSSLSizeFactory(new TagSizeFactory<>(Size.UnitType.BYTE));
        };
    }

    /** The {@code EVP_CIPHER_CTX_ctrl} call the resolved argument is written in. */
    @Nullable private static AstNode enclosingCall(@Nonnull AstNode tree) {
        for (AstNode node = tree; node != null; node = node.getParent()) {
            if (CxxAstNodeHelper.isFunctionCall(node)) {
                return "EVP_CIPHER_CTX_ctrl".equals(CxxAstNodeHelper.getFunctionCallName(node))
                        ? node
                        : null;
            }
        }
        return null;
    }
}
