"""Six-class FiLM input ablations on normalized 30-second feature tensors."""

import math
import torch
from torch import nn


def layer(inputs, outputs):
    return nn.Sequential(nn.Linear(inputs, outputs), nn.ReLU())


class TemporalEncoder(nn.Module):
    def __init__(self, inputs, width):
        super().__init__()
        self.project = nn.Conv1d(inputs, width, 1)
        self.blocks = nn.ModuleList()
        for dilation in (1, 2, 4, 8, 16):
            layers = []
            for _ in range(2):
                layers.extend(
                    (
                        nn.Conv1d(width, width, 3, dilation=dilation, padding=dilation),
                        nn.ReLU(),
                        nn.Dropout(0.1),
                    )
                )
            self.blocks.append(nn.Sequential(*layers))

    def forward(self, samples):
        x = self.project(samples.transpose(1, 2))
        for block in self.blocks:
            x = x + block(x)
        return torch.cat((x.mean(2), x.amax(2)), 1)


class TrafficEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.device_encoder = TemporalEncoder(40, 64)
        self.connection_static = layer(16, 32)
        self.connection_temporal = TemporalEncoder(2, 32)
        self.connection_fusion = layer(96, 64)
        self.set_projection = nn.Linear(129, 64)

    def forward(self, samples):
        device = self.device_encoder(torch.stack([s["device"] for s in samples]))
        counts = [len(s["connection_attributes"]) for s in samples]
        attributes = torch.cat([s["connection_attributes"] for s in samples])
        series = torch.cat([s["connection_temporal"] for s in samples])
        chunks = []
        for a, b in zip(attributes.split(128), series.split(128)):
            if len(a):
                chunks.append(
                    self.connection_fusion(
                        torch.cat((self.connection_static(a), self.connection_temporal(b)), 1)
                    )
                )
        pooled = device.new_zeros((len(samples), 64))
        if chunks:
            for i, group in enumerate(torch.cat(chunks).split(counts)):
                if len(group):
                    pooled[i] = self.set_projection(
                        torch.cat(
                            (
                                group.mean(0),
                                group.amax(0),
                                group.new_tensor([math.log1p(len(group))]),
                            )
                        )
                    )
        return torch.cat((device, pooled), 1)


class EvidenceModel(nn.Module):
    def __init__(self, view):
        super().__init__()
        if view not in ("traffic_only", "service_only", "joint"):
            raise ValueError(view)
        self.view = view
        self.traffic = TrafficEncoder()
        self.header_encoder = nn.Sequential(*layer(40, 64), *layer(64, 64))
        self.first = nn.Linear(256, 256)
        self.global_encoder = layer(3, 16)
        self.behavior_encoder = layer(324, 256)
        self.event_encoder = layer(44, 32)
        self.quality_encoder = layer(9, 16)
        self.reliability = nn.Linear(16, 1)
        self.mod = nn.Linear(304, 512)
        nn.init.zeros_(self.mod.weight)
        nn.init.zeros_(self.mod.bias)
        self.experts = nn.ModuleList(
            nn.Sequential(*layer(256, 128), nn.Dropout(0.2), nn.Linear(128, 6)) for _ in range(4)
        )
        self.gate = nn.Linear(560, 4)
        self.drop = nn.Dropout(0.2)

    def forward(self, samples, context):
        if context.shape != (len(samples), 380):
            raise ValueError("Expected a 380-channel service vector per sample")
        if self.view == "service_only":
            traffic = context.new_zeros((len(samples), 256))
            scale = torch.zeros_like(context[:, :3])
        else:
            traffic = torch.cat(
                (
                    self.traffic(samples),
                    self.header_encoder(torch.stack([s["header_profile"] for s in samples])),
                ),
                1,
            )
            scale = context[:, :3]
        service = torch.cat(
            (
                self.global_encoder(scale),
                self.behavior_encoder(context[:, 3:327]),
                self.event_encoder(context[:, 327:371]),
            ),
            1,
        )
        reliability = self.reliability(self.quality_encoder(context[:, 371:])).sigmoid()
        if self.view == "traffic_only":
            reliability = reliability * 0
            service = service * 0
        gamma, beta = self.mod(service).chunk(2, 1)
        hidden = self.drop(
            torch.relu(
                self.first(traffic) * (1 + (gamma * reliability).tanh()) + beta * reliability
            )
        )
        routing = self.gate(torch.cat((hidden, service * reliability), 1)).log_softmax(1)
        experts = torch.stack([head(hidden).log_softmax(1) for head in self.experts], 1)
        return torch.logsumexp(experts + routing[:, :, None], 1)
