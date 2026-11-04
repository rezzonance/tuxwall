#!/usr/bin/env python3
"""TuxWall/CrowdSec store housekeeping.

The custom-blocklist chain deliberately re-applies every blocklist entry as a
1-year ban on each CrowdSec restart/reload (see /etc/crowdsec/README-custom-
blocklist.md), so the permanent banlist survives engine restarts. The engine
does not dedupe those re-applies, so duplicate decisions (and orphaned alert
rows) accumulate and make `cscli decisions list` / LAPI queries progressively
more expensive (this was the root cause of the constant ~26% crowdsec CPU,
fixed 2026-11-03).

This script, run periodically (crowdsec-deduge.timer), makes the re-apply
idempotent:

1. Removes duplicate ACTIVE decisions, keeping the longest-lived ban per
   (value, scenario, type, origin). Nothing is unbanned - every distinct ban
   retains its maximum expiry.
2. Deletes alert-history rows older than 7 days that no longer hold any
   decision (pure history, no active ban attached; recent alerts are kept
   for the dashboard).

Safe to run while crowdsec is live (short IMMEDIATE transaction; retried on
next tick if the DB is busy).
"""

import sqlite3
import sys
import time

DB = "/var/lib/crowdsec/data/crowdsec.db"
ALERT_RETENTION_DAYS = 7


def main():
    now = time.time()
    db = sqlite3.connect(DB, timeout=15)
    c = db.cursor()
    try:
        c.execute("begin immediate")

        c.execute(
            """
            delete from decisions where id in (
                select id from (
                    select id,
                           row_number() over (
                               partition by value, scenario, type, origin
                               order by until desc, id desc
                           ) as rn
                    from decisions where until > ?
                ) where rn > 1)
            """,
            (now,),
        )
        dupes = c.execute("select changes()").fetchone()[0]

        c.execute(
            """
            delete from alerts where created_at < ? and not exists (
                select 1 from decisions d where d.alert_decisions = alerts.id)
            """,
            (now - ALERT_RETENTION_DAYS * 86400,),
        )
        orphans = c.execute("select changes()").fetchone()[0]

        db.commit()
    except sqlite3.OperationalError as exc:
        db.rollback()
        # Busy DB (engine writing) - not an error, next timer tick retries.
        print(f"busy, skipped this run: {exc}")
        sys.exit(0)
    finally:
        db.close()

    active = "n/a"
    try:
        ro = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10)
        active = ro.execute(
            "select count(*) from decisions where until > ?", (now,)
        ).fetchone()[0]
        ro.close()
    except sqlite3.OperationalError:
        pass
    print(
        f"crowdsec-dedupe: removed {dupes} duplicate decisions, "
        f"{orphans} orphaned alerts; active decisions now {active}"
    )


if __name__ == "__main__":
    main()
