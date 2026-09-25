from test.module import Foo

# b=42 must not also satisfy the wildcard positional slot a.
result = Foo.f(b=42, unused=0)
