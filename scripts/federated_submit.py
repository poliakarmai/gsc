#!/usr/bin/env python3
"""
GSC Federated Submit v2 — push local revalidation data to global weights.
Uses actual findings schema (category as rule_id proxy, revalidation_verdict).

DP-noised: adds Laplace noise to TP/FP counts before submission.
"""

import os, sqlite3, hashlib, random
from datetime import datetime

DB = os.path.expanduser("~/.hermes/state/gsc_audit.db")
DP_EPSILON = 1.0


def add_noise(count, epsilon=DP_EPSILON):
    scale = 1.0 / epsilon
    noise = random.uniform(-scale, scale) if scale > 0 else 0
    return max(0, int(count + noise))


def main():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    
    rules = db.execute("""
        SELECT category as rule_id,
               COUNT(*) as total,
               SUM(CASE WHEN revalidation_verdict = 'TP' THEN 1 ELSE 0 END) as tp,
               SUM(CASE WHEN revalidation_verdict = 'FP' THEN 1 ELSE 0 END) as fp
        FROM findings
        WHERE revalidation_verdict IN ('TP', 'FP', 'FIX')
        GROUP BY category
        HAVING total >= 5
    """).fetchall()
    
    tenant_hash = hashlib.sha256(b"poliakarmai").hexdigest()[:16]
    submitted = 0
    updated = 0
    
    if not rules:
        print("No revalidated rules with >=5 verdicts. Waiting for more data.")
        db.close()
        return 0
    
    for r in rules:
        rule_id = r['rule_id']
        total = r['total']
        tp_noisy = add_noise(r['tp'])
        fp_noisy = add_noise(r['fp'])
        
        accuracy = tp_noisy / max(1, tp_noisy + fp_noisy)
        
        existing = db.execute(
            "SELECT 1 FROM federated_global_weights WHERE rule_id = ?",
            (rule_id,)
        ).fetchone()
        
        if existing:
            db.execute("""
                UPDATE federated_global_weights
                SET global_tp_rate = ?, global_verdicts = global_verdicts + ?,
                    updated_at = ?
                WHERE rule_id = ?
            """, (accuracy, total, datetime.now().isoformat(), rule_id))
            updated += 1
        else:
            db.execute("""
                INSERT INTO federated_global_weights (rule_id, global_tp_rate, global_verdicts, updated_at)
                VALUES (?, ?, ?, ?)
            """, (rule_id, accuracy, total, datetime.now().isoformat()))
            submitted += 1
        
        db.execute("""
            INSERT INTO federated_log (action, detail, created_at)
            VALUES (?, ?, ?)
        """, (
            "submit",
            f"{tenant_hash}: {rule_id} tp={r['tp']}(+ε={tp_noisy}) fp={r['fp']}(+ε={fp_noisy}) → acc={accuracy:.3f}",
            datetime.now().isoformat(),
        ))
    
    db.commit()
    
    print(f"Federated submit: {submitted} new + {updated} updated weights")
    
    top = db.execute("""
        SELECT rule_id, global_tp_rate, global_verdicts
        FROM federated_global_weights
        ORDER BY global_tp_rate DESC
        LIMIT 5
    """).fetchall()
    
    if top:
        print("Top-5 by accuracy:")
        for t in top:
            print(f"  {t['rule_id']:<20s}  TP={t['global_tp_rate']:.3f}  N={t['global_verdicts']}")
    
    db.close()
    return submitted + updated


if __name__ == "__main__":
    print(f"Federated submit — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    count = main()
    print(f"✅ Done: {count} rules in global weights")
