from test.module import Foo

d = {"b": 42, "c": True}

# f("hello", **d) — dict-unpacking argument; contents cannot be statically inspected.
# The engine sees a non-RegularArgument in the argument list and rejects the call immediately
# in the unpacking-argument gate.
# → rule does NOT fire.
result = Foo.f("hello", **d)
