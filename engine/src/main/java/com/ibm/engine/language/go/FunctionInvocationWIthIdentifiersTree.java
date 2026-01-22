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
package com.ibm.engine.language.go;

import java.util.List;
import org.sonar.go.impl.FunctionInvocationTreeImpl;
import org.sonar.plugins.go.api.BlockTree;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.TreeMetaData;
import org.sonar.plugins.go.api.Type;

public final class FunctionInvocationWIthIdentifiersTree extends FunctionInvocationTreeImpl
        implements FunctionInvocationTree {
    private final List<IdentifierTree> identifiers;
    private final BlockTree blockTree;

    public FunctionInvocationWIthIdentifiersTree(
            TreeMetaData metaData,
            Tree memberSelect,
            List<Tree> arguments,
            List<Type> returnTypes,
            List<IdentifierTree> identifiers,
            BlockTree blockTree) {
        super(metaData, memberSelect, arguments, returnTypes);
        this.identifiers = identifiers;
        this.blockTree = blockTree;
    }

    public BlockTree getBlockTree() {
        return blockTree;
    }

    public List<IdentifierTree> getIdentifiers() {
        return identifiers;
    }
}
