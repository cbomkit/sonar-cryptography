from test.module import Foo

# c is optional but present with the wrong type: the root fires without a c child.
result = Foo.f("hello", b=42, c=42)
