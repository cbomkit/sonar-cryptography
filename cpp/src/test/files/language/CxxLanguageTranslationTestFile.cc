class Hasher {
  public:
    Hasher(const char *name);
    static Hasher make(const char *name);
    void reset(const char *name);
};

namespace crypto {
void helper(int value);
}

struct Api {
    const void *(*digest)(void);
};

enum Mode { FAST, SLOW };

void calls(Hasher &hasher, Hasher *pointer, Api *api, int count) {
    EVP_sha256();
    hasher.reset("SHA1");
    pointer->reset("SHA1");
    api->digest();
    Hasher::make("SHA256");
    crypto::helper(count);
    Hasher constructed("SHA224");
    use(32, "digest", 'c', count, count + 1, FAST);
}
