from test.module import Foo

# f(b=42) — only b is provided as a keyword; a's positional slot is missing entirely.
# arguments.size() = 1 < minArgs = 2, so the arity gate rejects the call.
# → rule does NOT fire.
result = Foo.f(b=42)
