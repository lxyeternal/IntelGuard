"""Two-level HDBSCAN clustering of KB snippets (code level, then behavior level).
Writes clusters.json and behavior_cluster_centroids.npy next to knowledge_base.json."""
import argparse
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

logger = logging.getLogger(__name__)

# predicates voted to label each behavior cluster
PREDICATES: List[Tuple[str, str]] = [
    ("data exfiltration", r"exfiltrat|sends? .*(?:to|towards) .*(?:server|domain|url|ip|endpoint|webhook)|upload.*(?:credential|token|data)|post(?:s|ing)? .*data"),
    ("credential theft", r"credential|token|password|secret|api[_ ]?key|ssh key|\.ssh|wallet|cookie|session"),
    ("remote code execution", r"remote code|download(?:s|ed|ing)? .*(?:execut|run)|execut.*(?:payload|binary|downloaded|remote)|curl .*\| ?(?:ba)?sh|wget .*\| ?(?:ba)?sh"),
    ("command execution", r"child_process|subprocess|os\.system|os\.popen|exec\(|spawn|shell command|powershell|cmd\.exe"),
    ("code injection / dynamic eval", r"\beval\b|new function|function constructor|dynamic(?:ally)? (?:execut|load)|compile\(|vm\.run"),
    ("persistence", r"persist|startup|cron|registry|scheduled task|autorun|systemd|launch agent|rc\.local"),
    ("reconnaissance / system info", r"hostname|username|system information|reconnaissance|fingerprint|network interface|os\.uname|platform|environment variables"),
    ("obfuscation / encoding", r"obfuscat|base64|hex[- ]encod|encoded|decode|xor|packed|minified"),
    ("backdoor / C2", r"backdoor|command[- ]and[- ]control|\bc2\b|reverse shell|beacon|botnet|rat\b"),
    ("install-time execution", r"preinstall|postinstall|install script|setup\.py|during installation|install[- ]time|lifecycle"),
    ("typosquatting / impersonation", r"typosquat|impersonat|masquerad|look-?alike|dependency confusion|namesquat"),
    ("crypto mining", r"xmrig|miner|mining|monero"),
    ("file tampering", r"delet(?:e|ing) files|overwrit|modif(?:y|ies) .*file|ransom|encrypt(?:s|ing) files|wipe"),
    ("anti-analysis / sandbox evasion", r"sandbox|virtual machine|anti-?(?:analysis|debug|vm)|evad|detect(?:s|ing)? (?:analysis|debugger)"),
]


def snippet_text(snippet: Dict[str, Any], package: Dict[str, Any]) -> str:
    m = snippet.get("malice_analysis", {}) or {}
    parts = [snippet.get("code_behavior", ""), m.get("why_suspicious", ""), m.get("violated_expectations", ""),
             " ".join(m.get("key_indicators", []) or []), str((snippet.get("execution_context") or {}).get("trigger", "")),
             package.get("package_info", {}).get("why_malicious", "")]
    return " ".join(p for p in parts if p).lower()


def predicates_of(text: str) -> List[str]:
    return [name for name, pat in PREDICATES if re.search(pat, text)]


def _l2(x: np.ndarray) -> np.ndarray:
    return x / (np.linalg.norm(x, axis=1, keepdims=True) + 1e-10)


def _hdbscan(x: np.ndarray, min_cluster_size: int, min_samples: int, eps: float = 0.0) -> np.ndarray:
    """HDBSCAN on L2-normalised vectors (euclidean distance there is monotone in cosine)."""
    xn = _l2(x.astype(np.float64))
    eps_euclid = float(eps)
    try:
        import hdbscan
        model = hdbscan.HDBSCAN(min_cluster_size=min_cluster_size, min_samples=min_samples, metric="euclidean",
                                cluster_selection_epsilon=eps_euclid, cluster_selection_method="eom", core_dist_n_jobs=-1)
    except ImportError:  # sklearn fallback, no epsilon
        from sklearn.cluster import HDBSCAN
        model = HDBSCAN(min_cluster_size=min_cluster_size, min_samples=min_samples, metric="euclidean",
                        cluster_selection_method="eom", n_jobs=-1)
    return model.fit_predict(xn)


def build_clusters(kb_dir: Path, code_min: int = 8, code_samples: int = 4,
                   beh_min: int = 40, beh_samples: int = 8, beh_eps: float = 0.45) -> Dict[str, Any]:
    with open(kb_dir / "knowledge_base.json", "r", encoding="utf-8") as f:
        kb = json.load(f)
    packages = kb["packages"]
    pk = {p["kb_id"]: p for p in packages}
    snippet_index = {int(k): tuple(v) for k, v in kb["metadata"]["snippet_index"].items()}
    code_emb = np.load(kb_dir / "snippet_code_embeddings.npy")
    beh_emb = np.load(kb_dir / "snippet_behavior_embeddings.npy")
    n = len(snippet_index)
    assert code_emb.shape[0] == n == beh_emb.shape[0], f"embeddings ({code_emb.shape[0]}, {beh_emb.shape[0]}) vs index ({n})"
    logger.info(f"clustering {n} snippets (code dim {code_emb.shape[1]}, behavior dim {beh_emb.shape[1]})")

    # empty snippets stay as noise (-1)
    valid_code = np.array([bool((pk[snippet_index[i][0]]["malicious_snippets"][snippet_index[i][1]].get("code_snippet") or "").strip()) for i in range(n)])
    valid_beh = np.array([bool((pk[snippet_index[i][0]]["malicious_snippets"][snippet_index[i][1]].get("code_behavior") or "").strip()) for i in range(n)])
    code_labels = np.full(n, -1, dtype=int)
    code_labels[valid_code] = _hdbscan(code_emb[valid_code], code_min, code_samples)
    beh_labels = np.full(n, -1, dtype=int)
    beh_labels[valid_beh] = _hdbscan(beh_emb[valid_beh], beh_min, beh_samples, beh_eps)
    logger.info(f"excluded from clustering: {int((~valid_code).sum())} empty-code, {int((~valid_beh).sum())} empty-behavior snippets")
    logger.info(f"level-1 code clusters: {len(set(code_labels)) - (1 if -1 in code_labels else 0)}, noise {int((code_labels == -1).sum())}")
    logger.info(f"level-2 behavior clusters: {len(set(beh_labels)) - (1 if -1 in beh_labels else 0)}, noise {int((beh_labels == -1).sum())}")

    def snippet(i: int):
        kb_id, j = snippet_index[i]
        return pk[kb_id], pk[kb_id]["malicious_snippets"][j]

    behn = _l2(beh_emb.astype(np.float64))
    behavior_clusters, centroids = [], []
    for cid in sorted(set(beh_labels) - {-1}):
        members = np.where(beh_labels == cid)[0]
        centroid = behn[members].mean(axis=0)
        centroid /= (np.linalg.norm(centroid) + 1e-10)
        sims = behn[members] @ centroid
        rep = int(members[int(np.argmax(sims))])
        votes, triggers, cats, pkgs = Counter(), Counter(), Counter(), set()
        for i in members:
            p, s = snippet(int(i))
            for pr in predicates_of(snippet_text(s, p)):
                votes[pr] += 1
            triggers[str((s.get("execution_context") or {}).get("trigger", "")).lower()[:40]] += 1
            pkgs.add(p["kb_id"])
            for c in (p["package_info"].get("package_manager") or "",):
                cats[str(c).lower()[:20]] += 1
        majority = [pr for pr, c in votes.most_common() if c >= max(2, 0.5 * len(members))]
        if not majority:
            majority = [pr for pr, _ in votes.most_common(3)]
        rp, rs = snippet(rep)
        behavior_clusters.append({
            "id": int(cid), "size": int(len(members)), "n_packages": len(pkgs), "members": [int(i) for i in members],
            "representative": rep, "representative_kb_id": rp["kb_id"], "representative_snippet_id": rs.get("snippet_id"),
            "representative_behavior": rs.get("code_behavior", ""),
            "predicates": majority, "predicate_votes": dict(votes.most_common(8)),
            "top_triggers": dict(triggers.most_common(3)), "ecosystems": dict(cats.most_common(4)),
            "unified_explanation": "; ".join(majority) if majority else "(no dominant predicate)",
            "cohesion": float(sims.mean()),
        })
        centroids.append(centroid.astype(np.float32))

    code_clusters = []
    for cid in sorted(set(code_labels) - {-1}):
        members = np.where(code_labels == cid)[0]
        code_clusters.append({"id": int(cid), "size": int(len(members)), "members": [int(i) for i in members],
                              "behavior_clusters": dict(Counter(int(beh_labels[i]) for i in members).most_common(5))})

    result = {
        "params": {"code": {"min_cluster_size": code_min, "min_samples": code_samples},
                   "behavior": {"min_cluster_size": beh_min, "min_samples": beh_samples, "epsilon": beh_eps}},
        "n_snippets": n,
        "code": code_clusters, "behavior": behavior_clusters,
        "snippet_code_cluster": [int(x) for x in code_labels],
        "snippet_behavior_cluster": [int(x) for x in beh_labels],
    }
    with open(kb_dir / "clusters.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)
    np.save(kb_dir / "behavior_cluster_centroids.npy", np.vstack(centroids) if centroids else np.zeros((0, beh_emb.shape[1]), dtype=np.float32))
    logger.info(f"saved {kb_dir / 'clusters.json'} and behavior_cluster_centroids.npy")
    return result


def main():
    ap = argparse.ArgumentParser(description="Two-level HDBSCAN clustering of the knowledge base")
    ap.add_argument("--kb", default=str(project_root / "KnowledgeBase"))
    ap.add_argument("--code-min", type=int, default=8)
    ap.add_argument("--code-samples", type=int, default=4)
    ap.add_argument("--beh-min", type=int, default=40)
    ap.add_argument("--beh-samples", type=int, default=8)
    ap.add_argument("--beh-eps", type=float, default=0.45)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    r = build_clusters(Path(args.kb), args.code_min, args.code_samples, args.beh_min, args.beh_samples, args.beh_eps)
    print(f"code clusters: {len(r['code'])}, behavior clusters: {len(r['behavior'])}, snippets: {r['n_snippets']}")
    for c in sorted(r["behavior"], key=lambda c: -c["size"])[:15]:
        print(f"  B{c['id']:>3} size={c['size']:4d} pkgs={c['n_packages']:4d} cohesion={c['cohesion']:.2f} | {c['unified_explanation']} | rep: {c['representative_behavior'][:90]}")


if __name__ == "__main__":
    main()
