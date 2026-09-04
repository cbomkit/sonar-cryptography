package com.ibm.plugin.rules.detection.nodecrypto;

import javax.annotation.Nonnull;

class NodeCryptoRandomTest extends NodeCryptoRuleTestBase {
    @Override
    @Nonnull
    protected String fixturePath() {
        return "rules/detection/nodecrypto/NodeCryptoRandomTestFile.js";
    }
}
