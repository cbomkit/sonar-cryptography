class Hasher {
  public:
    Hasher(const char *name);
    Hasher(const char *name, int size);
};

class Config {};

namespace crypto {
class Digest {
  public:
    Digest(const char *name);
};
} // namespace crypto

void declarations(const char *name, int size, Hasher *other) {
    Hasher parenthesized("SHA224");
    Hasher braced{"SHA384"};
    Hasher bracedTwo{"SHA256", 32};
    Hasher copyList = {"SHA512"};
    const Hasher qualified("SHA1", 32);
    Hasher names(name, size);
    crypto::Digest namespaced("MD5");
    Hasher function(Config);
    Hasher noArguments;
    Hasher copied = *other;
    Hasher array[1]{"SHA256"};
    int builtIn(32);
    Hasher("SHA3-256");
    Hasher{"SHA3-384"};
    crypto::Digest("SHA3-512");
    new Hasher("SHAKE128", 16);
    other->reset("x");
}
