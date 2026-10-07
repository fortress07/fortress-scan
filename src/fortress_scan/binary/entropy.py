from __future__ import annotations

import math
from collections import Counter

# Dưới ngưỡng này entropy dao động quá mạnh theo vài byte, nên không đáng kết luận.
MIN_SAMPLE = 256


def shannon(data: bytes) -> float:
    """Entropy Shannon theo bit/byte, 0.0 tới 8.0."""
    if not data:
        return 0.0
    total = len(data)
    result = 0.0
    for count in Counter(data).values():
        probability = count / total
        result -= probability * math.log2(probability)
    return result
