"""Read and write the six-class traffic-header model and its fitted statistics."""

import torch

from .model import ActivityFiLM, LABELS, SCHEMA


def save_model(path, model, stats):
    context = stats["context"]
    torch.save({
        "state": model.state_dict(),
        "traffic_normalizer": {k: v for k, v in stats.items() if k != "context"},
        "context_mean": torch.tensor(context["mean"], dtype=torch.float64),
        "context_std": torch.tensor(context["std"], dtype=torch.float64),
        "plan": {"model_schema": SCHEMA, "labels": list(LABELS),
                 "film_options": {"profile_width": 40, "header_width": 64, "evidence_dropout": 0.0}},
    }, path)


def load_model(path, device="cpu"):
    package = torch.load(path, map_location="cpu", weights_only=True)
    plan = package["plan"]
    if plan["model_schema"] != SCHEMA or tuple(plan["labels"]) != LABELS:
        raise ValueError("Expected a six-class traffic-header FiLM checkpoint")
    if plan.get("film_options") != {"profile_width": 40, "header_width": 64, "evidence_dropout": 0.0}:
        raise ValueError("Unexpected encoder or service-gate configuration")
    model = ActivityFiLM()
    model.load_state_dict(package["state"], strict=True)
    stats = {**package["traffic_normalizer"], "context": {
        "mean": package["context_mean"].numpy(), "std": package["context_std"].numpy()}}
    return model.to(device).eval(), stats
