"""Device and connection encoders with reliability-gated service conditioning."""

import math

import torch
from torch import nn
from torch.nn import functional as F

LABELS = ("background", "browsing", "live_stream", "long_video", "music", "short_video")
SCHEMA = "screen_behavior.structured_service_film.six_class.traffic_header_reliable.v1"


class TemporalEncoder(nn.Module):
    def __init__(self, channels, width):
        super().__init__()
        self.project = nn.Conv1d(channels, width, 1)
        self.blocks = nn.ModuleList()
        for dilation in (1, 2, 4, 8, 16):
            layers = []
            for _ in range(2):
                layers.extend((nn.Conv1d(width, width, 3, padding=dilation, dilation=dilation),
                               nn.ReLU(), nn.Dropout(0.1)))
            self.blocks.append(nn.Sequential(*layers))

    def forward(self, sequence):
        x = self.project(sequence.transpose(1, 2))
        for block in self.blocks:
            x = x + block(x)
        return torch.cat((x.mean(2), x.amax(2)), dim=1)


class TrafficEncoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.device_encoder = TemporalEncoder(40, 64)
        self.connection_static = nn.Sequential(nn.Linear(16, 32), nn.ReLU())
        self.connection_temporal = TemporalEncoder(2, 32)
        self.connection_fusion = nn.Sequential(nn.Linear(96, 64), nn.ReLU())
        self.set_projection = nn.Linear(129, 64)

    def forward(self, rows):
        device = self.device_encoder(torch.stack([r["device"] for r in rows]))
        attrs = [r["connection_attributes"] for r in rows]
        counts = [len(a) for a in attrs]
        static = torch.cat(attrs)
        temporal = torch.cat([r["connection_temporal"] for r in rows])
        encoded = []
        for start in range(0, len(static), 128):
            block = slice(start, start + 128)
            x = self.connection_static(static[block])
            y = self.connection_temporal(temporal[block])
            encoded.append(self.connection_fusion(torch.cat((x, y), dim=1)))
        if encoded:
            pooled = []
            for n, flows in zip(counts, torch.cat(encoded).split(counts), strict=True):
                if n:
                    size = flows.new_tensor([math.log1p(n)])
                    pooled.append(self.set_projection(torch.cat((flows.mean(0), flows.amax(0), size))))
                else:
                    pooled.append(device.new_zeros(64))
            connections = torch.stack(pooled)
        else:
            connections = device.new_zeros((len(rows), 64))
        return torch.cat((device, connections), dim=1)


class ActivityFiLM(nn.Module):
    def __init__(self):
        super().__init__()
        self.traffic = TrafficEncoder()
        self.header_encoder = nn.Sequential(nn.Linear(40, 64), nn.ReLU(), nn.Linear(64, 64), nn.ReLU())
        self.first = nn.Linear(256, 256)
        self.global_encoder = nn.Sequential(nn.Linear(3, 16), nn.ReLU())
        self.behavior_encoder = nn.Sequential(nn.Linear(324, 256), nn.ReLU())
        self.event_encoder = nn.Sequential(nn.Linear(44, 32), nn.ReLU())
        self.quality_encoder = nn.Sequential(nn.Linear(9, 16), nn.ReLU())
        self.reliability = nn.Linear(16, 1)
        self.mod = nn.Linear(304, 512)
        nn.init.zeros_(self.mod.weight)
        nn.init.zeros_(self.mod.bias)
        self.drop = nn.Dropout(0.2)
        self.experts = nn.ModuleList(
            nn.Sequential(nn.Linear(256, 128), nn.ReLU(), nn.Dropout(0.2), nn.Linear(128, len(LABELS)))
            for _ in range(4)
        )
        self.gate = nn.Linear(560, 4)

    def forward(self, rows, context):
        header = self.header_encoder(torch.stack([r["header_profile"] for r in rows]))
        traffic = self.first(torch.cat((self.traffic(rows), header), dim=1))
        service = torch.cat((self.global_encoder(context[:, :3]),
                             self.behavior_encoder(context[:, 3:327]),
                             self.event_encoder(context[:, 327:371])), dim=1)
        reliability = self.reliability(self.quality_encoder(context[:, 371:])).sigmoid()
        gamma, beta = self.mod(service).chunk(2, dim=1)
        hidden = self.drop(F.relu(traffic * (1 + (reliability * gamma).tanh()) + reliability * beta))
        weights = self.gate(torch.cat((hidden, reliability * service), dim=1)).log_softmax(1)
        experts = torch.stack([expert(hidden).log_softmax(1) for expert in self.experts], dim=1)
        return torch.logsumexp(experts + weights.unsqueeze(2), dim=1)
