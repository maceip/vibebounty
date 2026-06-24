import importlib

mods = [
    "numpy",
    "torch",
    "transformers",
    "trl",
    "peft",
    "datasets",
    "accelerate",
    "huggingface_hub",
]
for m in mods:
    try:
        mod = importlib.import_module(m)
        print(f"{m:16s} {getattr(mod, '__version__', '?')}")
    except Exception as e:
        print(f"{m:16s} MISSING ({e})")
