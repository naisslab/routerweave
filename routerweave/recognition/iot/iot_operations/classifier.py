"""Operation recognition from candidate members, preceding traffic and device identity."""

import numpy as np
import torch
from torch import nn
from torch.nn import functional as F


SIZE_PERIODS = 2 ** np.arange(1, 12)


def size_features(tokens):
    sizes = np.rint(np.expm1(tokens[:, 0])).astype(np.float64)
    directions = np.sign(tokens[:, 1])
    angles = 2 * np.pi * sizes[:, None] / SIZE_PERIODS
    previous = np.r_[sizes[0], sizes[:-1]]
    last = {}
    deltas = np.empty_like(sizes)
    for i, (size, direction) in enumerate(zip(sizes, directions)):
        deltas[i] = size - last.get(direction, size)
        last[direction] = size

    def signed_log(values):
        return np.sign(values) * np.log1p(np.abs(values)) / 4

    return np.column_stack((np.sin(angles), np.cos(angles), sizes / 1500,
                            signed_log(sizes - previous), signed_log(deltas),
                            (sizes % 16) / 16, directions)).astype(np.float32)


class ConditionedExperts(nn.Module):
    def __init__(self, classes):
        super().__init__()
        self.traffic = nn.Sequential(nn.Linear(168, 128), nn.ReLU(), nn.Linear(128, 96), nn.ReLU())
        self.context = nn.Sequential(nn.Linear(58, 96), nn.ReLU(), nn.Linear(96, 48), nn.ReLU())
        self.quality = nn.Sequential(nn.Linear(3, 16), nn.ReLU(), nn.Linear(16, 1))
        self.first = nn.Linear(96, 96)
        self.mod = nn.Linear(48, 192)
        nn.init.zeros_(self.mod.weight)
        nn.init.zeros_(self.mod.bias)
        # The study initialized a concatenation projection here before the expert
        # weights. Consume the same CPU RNG draws to reproduce a seeded refit.
        nn.Linear(self.first.out_features + self.mod.in_features, self.first.out_features)
        self.drop = nn.Dropout(0.2)
        self.gate = nn.Linear(144, 4)
        self.experts = nn.ModuleList(
            nn.Sequential(nn.Linear(96, 48), nn.ReLU(), nn.Dropout(0.2), nn.Linear(48, classes))
            for _ in range(4)
        )

    def forward(self, traffic, context, quality):
        encoded = self.traffic(traffic)
        context = self.context(context)
        gamma, beta = self.mod(context).chunk(2, dim=1)
        reliability = self.quality(quality).sigmoid()
        hidden = self.drop(F.relu(self.first(encoded) * (1 + gamma.tanh() * reliability)
                                  + beta * reliability))
        routing = self.gate(torch.cat((hidden, context), 1)).log_softmax(1)
        experts = torch.stack([expert(hidden).log_softmax(1) for expert in self.experts], 1)
        return torch.logsumexp(experts + routing[:, :, None], 1)


class OperationClassifier(nn.Module):
    def __init__(self, normalization, support):
        super().__init__()
        for name, values in normalization.items():
            self.register_buffer(name, torch.as_tensor(values, dtype=torch.float32))
        self.register_buffer("support", torch.as_tensor(support, dtype=torch.bool))
        devices, classes = self.support.shape
        self.device_embedding = nn.Embedding(devices, 16)
        self.packet = nn.Sequential(nn.Linear(12, 32), nn.GELU())
        self.sequence = nn.GRU(32, 32, batch_first=True, bidirectional=True)
        self.film = ConditionedExperts(classes)
        self.size_encoder = nn.Sequential(nn.Linear(2 * len(SIZE_PERIODS) + 5, 32), nn.GELU())
        self.mix = nn.Sequential(nn.Linear(64, 32), nn.GELU())

    def forward(self, tokens, lengths, flat, history, quality, devices, numeric):
        packet = self.packet((tokens - self.token_mean) / self.token_scale)
        sequence = self.mix(torch.cat((packet, self.size_encoder(numeric)), -1))
        packed = nn.utils.rnn.pack_padded_sequence(sequence, lengths, batch_first=True, enforce_sorted=False)
        encoded, _ = self.sequence(packed)
        encoded, _ = nn.utils.rnn.pad_packed_sequence(encoded, batch_first=True)
        counts = torch.as_tensor(lengths, device=tokens.device)
        valid = torch.arange(encoded.shape[1], device=tokens.device)[None] < counts[:, None]
        mean = encoded.sum(1) / counts[:, None]
        maximum = encoded.masked_fill(~valid[:, :, None], -1e9).max(1).values
        traffic = torch.cat((mean, maximum, (flat - self.flat_mean) / self.flat_scale), 1)
        conditions = torch.cat(((history - self.context_mean) / self.context_scale,
                                self.device_embedding(devices)), 1)
        logp = self.film(traffic, conditions, quality)
        return logp.masked_fill(~self.support[devices], -1e9).log_softmax(1)

    def probabilities(self, traffic, candidate, device_id):
        tokens, flat, context, quality = traffic.candidate(candidate.packet_indices)
        arrays = (tokens, flat, context, quality, size_features(tokens))
        device = self.support.device
        x, f, c, q, sizes = (torch.as_tensor(a, device=device)[None] for a in arrays)
        devices = torch.tensor([device_id], device=device)
        return self(x, [len(tokens)], f, c, q, devices, sizes)[0].exp()
