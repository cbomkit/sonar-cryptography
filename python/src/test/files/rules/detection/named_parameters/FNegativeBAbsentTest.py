from test.module import Foo

# f("hello") — only a present; b (required named) is absent.
# minArgs = 2 (positional a + required named b); arguments.size() = 1 < 2.
# The arity gate rejects the call before any type checks run.
# → rule does NOT fire.
result = Foo.f("hello")
