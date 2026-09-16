"""RF channel optimizer.

2.4 GHz: channels 1/6/11 are treated as the ONLY non-overlapping set, with a
penalty for networks on adjacent channels (overlap decays with channel
distance, 20 MHz channels are 5 MHz apart).
5 GHz:   channels scored independently (they are all non-overlapping at
20 MHz width); the least-congested observed channel wins.
"""
from __future__ import annotations

CHANNELS_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
NON_OVERLAPPING_24 = [1, 6, 11]
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
              124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]


def _overlap_penalty(distance: int) -> float:
    """20 MHz channel width, 5 MHz spacing -> overlap fades by ~5 MHz steps."""
    if distance == 0:
        return 1.0
    if distance < 4:
        return 1.0 - distance / 4.0
    return 0.0


def _score_channel(channel: int, networks) -> float:
    """Congestion score = sum of signal-weight * overlap penalty."""
    score = 0.0
    for n in networks:
        if n.channel is None:
            continue
        weight = (n.signal_strength or 0) / 100.0
        score += weight * _overlap_penalty(abs(channel - n.channel))
    return round(score, 3)


def recommend(networks) -> dict:
    """Return per-band recommendation + congestion table."""
    nets_24 = [n for n in networks if n.band == "2.4"]
    nets_5 = [n for n in networks if n.band == "5"]

    out: dict = {"recommendations": {}, "congestion": {}}

    if nets_24:
        scores = {ch: _score_channel(ch, nets_24) for ch in CHANNELS_24}
        out["congestion"]["2.4"] = scores
        # only the non-overlapping trio is eligible for the recommendation
        best = min(NON_OVERLAPPING_24, key=lambda ch: scores[ch])
        out["recommendations"]["2.4"] = {
            "channel": best,
            "score": scores[best],
            "note": "Channels 1/6/11 are the only non-overlapping set in "
                    "2.4 GHz; adjacent channels are penalised.",
        }
    else:
        out["recommendations"]["2.4"] = {
            "channel": 1, "score": 0.0,
            "note": "No 2.4 GHz networks observed — channel 1 is a safe "
                    "default (or 6/11).",
        }

    if nets_5:
        scores = {ch: _score_channel(ch, nets_5) for ch in CHANNELS_5}
        out["congestion"]["5"] = scores
        best = min(scores, key=scores.get)
        out["recommendations"]["5"] = {
            "channel": best, "score": scores[best],
            "note": "5 GHz channels are independent; the least-congested "
                    "observed channel is recommended.",
        }
    else:
        out["recommendations"]["5"] = {
            "channel": 36, "score": 0.0,
            "note": "No 5 GHz networks observed — channel 36 is a safe "
                    "default.",
        }

    return out
