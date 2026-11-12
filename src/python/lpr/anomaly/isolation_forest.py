"""Small Isolation Forest (Liu et al., 2008), matching the original implementation.

Trees are grown with the same seeded random sequence as before, so the same
data always gets the same scores. Scoring is vectorised with numpy.
"""
from __future__ import annotations

import math

import numpy as np

from ..jsutil import mulberry32

EULER = 0.5772156649


def average_path_length(n: int) -> float:
    """Average path length of an unsuccessful BST search over n points."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2 * (math.log(n - 1) + EULER) - (2 * (n - 1)) / n


class _Tree:
    __slots__ = ("feature", "threshold", "left", "right", "leaf_value", "depth")

    def __init__(self):
        self.feature: list[int] = []
        self.threshold: list[float] = []
        self.left: list[int] = []
        self.right: list[int] = []
        self.leaf_value: list[float] = []
        self.depth = 0

    def new_node(self) -> int:
        self.feature.append(-1)
        self.threshold.append(0.0)
        self.left.append(0)
        self.right.append(0)
        self.leaf_value.append(0.0)
        return len(self.feature) - 1

    def freeze(self):
        for i, f in enumerate(self.feature):
            if f < 0:  # leaf: any comparison keeps the walk on this node
                self.feature[i] = 0
                self.left[i] = i
                self.right[i] = i
        self.feature = np.array(self.feature, dtype=np.int64)
        self.threshold = np.array(self.threshold, dtype=np.float64)
        self.left = np.array(self.left, dtype=np.int64)
        self.right = np.array(self.right, dtype=np.int64)
        self.leaf_value = np.array(self.leaf_value, dtype=np.float64)


class IsolationForest:
    def __init__(self, n_trees: int = 150, sample_size: int = 256, seed=42):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees: list[_Tree] = []
        self.psi = 0
        self.max_depth = 0

    def fit(self, X: list[list[float]]) -> "IsolationForest":
        rng = mulberry32(self.seed)
        n = len(X)
        self.psi = min(self.sample_size, n)
        self.max_depth = math.ceil(math.log2(max(self.psi, 2)))
        idx = list(range(n))
        self.trees = []
        for _ in range(self.n_trees):
            # partial Fisher-Yates: first psi entries become the sample
            for i in range(self.psi):
                j = i + math.floor(rng() * (n - i))
                idx[i], idx[j] = idx[j], idx[i]
            sample = [X[i] for i in idx[: self.psi]]
            tree = _Tree()
            self._build(tree, sample, 0, rng)
            tree.freeze()
            self.trees.append(tree)
        return self

    def _build(self, tree: _Tree, rows: list[list[float]], depth: int, rng) -> int:
        node = tree.new_node()
        tree.depth = max(tree.depth, depth)
        if depth >= self.max_depth or len(rows) <= 1:
            tree.leaf_value[node] = depth + average_path_length(len(rows))
            return node
        candidates = []
        for f, col in enumerate(zip(*rows)):
            lo, hi = min(col), max(col)
            if hi > lo:
                candidates.append((f, lo, hi))
        if not candidates:
            tree.leaf_value[node] = depth + average_path_length(len(rows))
            return node
        f, lo, hi = candidates[math.floor(rng() * len(candidates))]
        s = lo + rng() * (hi - lo)
        left = [r for r in rows if r[f] < s]
        right = [r for r in rows if not (r[f] < s)]
        tree.feature[node] = f
        tree.threshold[node] = s
        tree.left[node] = self._build(tree, left, depth + 1, rng)
        tree.right[node] = self._build(tree, right, depth + 1, rng)
        return node

    def score_matrix(self, X) -> np.ndarray:
        """Anomaly scores in (0, 1] for every row; near 1 is anomalous."""
        if not self.trees:
            raise RuntimeError("IsolationForest: call fit() first")
        X = np.ascontiguousarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        n, dims = X.shape
        flat = X.ravel()
        base = np.arange(n, dtype=np.int64) * dims
        total = np.zeros(n, dtype=np.float64)
        for tree in self.trees:
            node = np.zeros(n, dtype=np.int64)
            for _ in range(tree.depth):
                values = flat.take(base + tree.feature.take(node))
                node = np.where(values < tree.threshold.take(node), tree.left.take(node), tree.right.take(node))
            total += tree.leaf_value.take(node)
        mean = total / len(self.trees)
        return np.power(2.0, -mean / average_path_length(self.psi))

    def score(self, x: list[float]) -> float:
        return float(self.score_matrix([x])[0])
