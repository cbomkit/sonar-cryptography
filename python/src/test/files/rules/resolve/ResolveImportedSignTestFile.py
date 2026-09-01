from imports.ResolveImportedSignImport import custom_sign

data = b"A message I want to sign"
signature = custom_sign(data)