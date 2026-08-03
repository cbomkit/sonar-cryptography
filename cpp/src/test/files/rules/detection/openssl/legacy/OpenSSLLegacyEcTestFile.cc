#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>

// Scoped enum (C++11 enum class): its constants are reachable only via a qualified
// reference (CurveNid::P256), not the normal enclosing-scope chain.
enum class CurveNid : int { P256 = 415 };

void test_legacy_ec() {
    EC_KEY* key = NULL;
    EC_GROUP* grp = NULL;
    EC_POINT* pt = NULL;
    BIGNUM* bn = NULL;
    BN_CTX* ctx = NULL;
    unsigned char buf[64];
    unsigned int siglen = 0;

    EC_KEY_new_by_curve_name(415);
    EC_KEY_new_by_curve_name_ex(NULL, NULL, 415);
    EC_KEY_generate_key(key);
    EC_KEY_set_group(key, grp);

    // Curve NID via a local variable, not a literal.
    int p256_nid = 415;
    EC_KEY_new_by_curve_name(p256_nid);

    // Curve NID via a scoped-enum qualified reference, resolved through
    // CxxSymbolResolverVisitor's TypeSymbol#memberScope lookup.
    EC_KEY_new_by_curve_name(CurveNid::P256);

    ECDSA_sign(0, buf, 32, buf, &siglen, key);
    ECDSA_do_sign(buf, 32, key);
    ECDSA_sign_ex(0, buf, 32, buf, &siglen, bn, bn, key);
    ECDSA_do_sign_ex(buf, 32, bn, bn, key);

    EC_GROUP_new_by_curve_name(415);
    EC_GROUP_new_by_curve_name_ex(NULL, NULL, 415);
    EC_GROUP_new_curve_GFp(bn, bn, bn, ctx);
    EC_GROUP_new_curve_GF2m(bn, bn, bn, ctx);
    EC_GROUP_new_from_ecparameters(NULL);
    EC_GROUP_new_from_ecpkparameters(NULL);
    EC_GROUP_new_from_params(NULL, NULL, NULL);
}
