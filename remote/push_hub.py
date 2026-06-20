"""Create (if needed) and push a fused model folder to the Hugging Face Hub.

    python push_hub.py <repo_name> <folder>
Auth via the HF_TOKEN environment variable.
"""
import sys

from huggingface_hub import create_repo, upload_folder

name = sys.argv[1] if len(sys.argv) > 1 else "vibebounty"
folder = sys.argv[2] if len(sys.argv) > 2 else "vibethinker-bbtriage"

repo = create_repo(name, repo_type="model", exist_ok=True)
print("repo:", repo.repo_id)
upload_folder(
    folder_path=folder,
    repo_id=repo.repo_id,
    repo_type="model",
    commit_message="VibeBounty: VibeThinker-3B LoRA fine-tuned for bug-bounty triage",
)
print("uploaded ->", f"https://huggingface.co/{repo.repo_id}")
