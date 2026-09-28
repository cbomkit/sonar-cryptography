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

import com.sonar.cxx.sslr.api.AstNode;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.AstNodeTraversal;
import org.sonar.cxx.squidbridge.api.AstNodeTypeExtension;

/**
 * Removes a file's entries from the {@link AstNodeSymbolExtension} and {@link AstNodeTypeExtension}
 * maps once every detection rule of the scan has finished with that file.
 *
 * <p>Both maps are process-wide and shared by all checks. sonar-cxx calls {@code leaveFile} on each
 * check in turn, so the entries of a file can only be removed after the last of our rules has
 * processed it; removing them earlier leaves the remaining rules without symbol information.
 *
 * <p>Rules register in {@code init()}, which sonar-cxx calls once per scan, and report in {@code
 * leaveFile}. Rules are grouped by the {@link SquidAstVisitorContext} of their scan, since all
 * checks of one scan share that context.
 */
final class CxxSymbolExtensionRelease {

    private static final Map<SquidAstVisitorContext<?>, CxxSymbolExtensionRelease> BY_CONTEXT =
            new WeakHashMap<>();

    private final Set<CxxBaseDetectionRule> registeredRules =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<CxxBaseDetectionRule> rulesDoneWithFile =
            Collections.newSetFromMap(new IdentityHashMap<>());
    @Nullable private AstNode currentFile;

    private CxxSymbolExtensionRelease() {
        // created per scan context
    }

    static synchronized void register(
            @Nonnull SquidAstVisitorContext<?> context, @Nonnull CxxBaseDetectionRule rule) {
        BY_CONTEXT
                .computeIfAbsent(context, c -> new CxxSymbolExtensionRelease())
                .registeredRules
                .add(rule);
    }

    /**
     * Records that {@code rule} has finished with the file rooted at {@code fileRoot}, and removes
     * the file's symbol and type entries if it was the last registered rule to do so.
     */
    static synchronized void leaveFile(
            @Nonnull SquidAstVisitorContext<?> context,
            @Nonnull CxxBaseDetectionRule rule,
            @Nonnull AstNode fileRoot) {
        final CxxSymbolExtensionRelease release = BY_CONTEXT.get(context);
        if (release == null || !release.registeredRules.contains(rule)) {
            // rule was not initialized by a scanner, so no other rule depends on this file
            removeEntries(fileRoot);
            return;
        }
        if (release.currentFile != fileRoot) {
            release.currentFile = fileRoot;
            release.rulesDoneWithFile.clear();
        }
        release.rulesDoneWithFile.add(rule);
        if (release.rulesDoneWithFile.containsAll(release.registeredRules)) {
            removeEntries(fileRoot);
            release.currentFile = null;
            release.rulesDoneWithFile.clear();
        }
    }

    private static void removeEntries(@Nonnull AstNode fileRoot) {
        AstNodeTraversal.traverse(
                fileRoot,
                node -> {
                    AstNodeSymbolExtension.removeSymbol(node);
                    AstNodeTypeExtension.removeType(node);
                });
    }
}
