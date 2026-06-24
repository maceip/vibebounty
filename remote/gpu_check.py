import torch

print("torch", torch.__version__)
print("cuda?", torch.cuda.is_available())
if torch.cuda.is_available():
    print("device", torch.cuda.get_device_name(0))
    print("capability", torch.cuda.get_device_capability(0))
    print("bf16", torch.cuda.is_bf16_supported())
