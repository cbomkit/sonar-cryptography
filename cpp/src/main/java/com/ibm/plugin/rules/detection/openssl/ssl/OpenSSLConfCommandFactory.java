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
package com.ibm.plugin.rules.detection.openssl.ssl;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.language.cxx.CxxSemantic;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.factory.IValueFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * Resolves the setting made by {@code SSL_CONF_cmd(cctx, cmd, value)} when {@code cmd} is one of
 * the given commands, e.g. {@code "CipherString"} and its command line form {@code "-cipher"}. The
 * factory is applied to the {@code cmd} argument; the {@code value} argument of the same call is
 * resolved and handed to {@code valueFactory}, which gives the result. Any other command, or a
 * {@code cmd} that is not given at the call, resolves to nothing.
 */
public final class OpenSSLConfCommandFactory implements IValueFactory<AstNode> {

    private static final int VALUE_ARGUMENT = 2;

    @Nonnull private final Set<String> commands;
    @Nonnull private final IValueFactory<AstNode> valueFactory;

    public OpenSSLConfCommandFactory(
            @Nonnull Set<String> commands, @Nonnull IValueFactory<AstNode> valueFactory) {
        this.commands =
                commands.stream()
                        .map(command -> command.toLowerCase(Locale.ROOT))
                        .collect(Collectors.toUnmodifiableSet());
        this.valueFactory = valueFactory;
    }

    @Override
    @Nonnull
    public Optional<IValue<AstNode>> apply(@Nonnull ResolvedValue<Object, AstNode> resolvedValue) {
        if (!(resolvedValue.value() instanceof String command)
                || !commands.contains(command.trim().toLowerCase(Locale.ROOT))) {
            return Optional.empty();
        }
        final AstNode call = enclosingCall(resolvedValue.tree());
        if (call == null) {
            return Optional.empty();
        }
        final List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(call);
        if (arguments.size() <= VALUE_ARGUMENT) {
            return Optional.empty();
        }
        final AstNode valueArgument = arguments.get(VALUE_ARGUMENT);
        for (ResolvedValue<Object, AstNode> value :
                CxxSemantic.resolveValues(
                        Object.class, valueArgument, new LinkedList<>(), null, false, null)) {
            final Optional<IValue<AstNode>> setting = valueFactory.apply(value);
            if (setting.isPresent()) {
                return setting;
            }
        }
        return Optional.empty();
    }

    /**
     * The {@code SSL_CONF_cmd} call of the command: the tree of a value resolved at the call is the
     * call itself, otherwise the call the value is written in.
     */
    @Nullable private static AstNode enclosingCall(@Nonnull AstNode tree) {
        for (AstNode node = tree; node != null; node = node.getParent()) {
            if (CxxAstNodeHelper.isFunctionCall(node)) {
                return "SSL_CONF_cmd".equals(CxxAstNodeHelper.getFunctionCallName(node))
                        ? node
                        : null;
            }
        }
        return null;
    }
}
