from test.module import Foo

# An unrelated keyword in slot 0 does not supply the positional parameter a.
result = Foo.f(unused="hello", b=42)
