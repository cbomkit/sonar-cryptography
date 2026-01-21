package com.ibm.engine.language.go;

import org.sonar.go.impl.FunctionInvocationTreeImpl;
import org.sonar.plugins.go.api.BlockTree;
import org.sonar.plugins.go.api.FunctionInvocationTree;
import org.sonar.plugins.go.api.IdentifierTree;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.TreeMetaData;
import org.sonar.plugins.go.api.Type;

import java.util.List;

public class FunctionInvocationWIthIdentifiersTree extends FunctionInvocationTreeImpl implements FunctionInvocationTree {
    private final List<IdentifierTree> identifiers;
    private final BlockTree blockTree;

    public FunctionInvocationWIthIdentifiersTree(TreeMetaData metaData,
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
