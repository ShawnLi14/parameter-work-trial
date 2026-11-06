"""Self-improving reviewer: find-verify running on a profile learned for the model.

The profile (finder guidance, verifier criteria, specialists) for a model lives in
profiles/<model>.json. `python -m benchmark improve` learns it from the reviewer's own
benchmark failures and writes it there when the loop finishes. A model with no learned
profile yet runs on find-verify's default profile, which the output metadata records.
"""

from pathlib import Path

from .. import find_verify

PROFILES = Path(__file__).resolve().parent / "profiles"


def profile_path(model):
    return PROFILES / f"{model}.json"


def load(model):
    """The learned profile for this model, or find-verify's default if none exists yet."""
    path = profile_path(model)
    return find_verify.load_profile(path if path.exists() else None), path.exists()


def review(context, api_key, *, model, profile=None, **options):
    learned = None
    if profile is None:
        profile, learned = load(model)
    result = find_verify.review(context, api_key, model=model, profile=profile, **options)
    result["metadata"]["scope"] = "self_improving"
    result["metadata"]["learned_profile"] = learned
    return result
