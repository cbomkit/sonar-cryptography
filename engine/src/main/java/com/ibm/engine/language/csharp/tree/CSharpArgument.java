package com.ibm.engine.language.csharp.tree;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public record CSharpArgument(@Nullable String name, @Nonnull CSharpTree value) {
    public boolean isNamed() {
        return name != null;
    }
}
