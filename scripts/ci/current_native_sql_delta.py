def sql_commit_delta(before_snapshot, after_snapshot):
    """Read the additive SQL child; never changes snapshots or caller outcomes."""
    sites = ("admission_persistence", "atomic", "reorg_step", "reorg_termination")
    counters = (
        "calls_started", "calls_returned", "calls_succeeded", "calls_failed",
        "calls_abandoned", "calls_unwinding", "cpu_ns_known_sum",
        "wall_unknown_calls", "cpu_known_calls", "cpu_unknown_calls",
    )
    timings = ("wall_ns", "cpu_ns")
    result = {
        "schema": "pon-native-sql-commit-delta-readback-v1",
        "has_consensus_authority": False,
        "status": "unknown", "sites": [],
        "scope": (
            "Same-owner cumulative snapshots only; caller must bind source and owner. "
            "Returned/abandoned counters and wall_ns describe calls ending between snapshots; "
            "started counts entries and in-flight is a gauge. Boundary calls may include "
            "time outside the interval. Complete interval "
            "wall/CPU require zero in-flight calls at both boundaries. CPU is the "
            "calling thread only. Unentered/unknown is not measured zero. API Ok is "
            "not business success; pre-entry refusals/cancellations remain in caller "
            "outcomes. Nested times are not additive; no physical fsync attribution."
        ),
    }

    def need(condition, reason):
        if not condition:
            raise ValueError(reason)

    def uint(value):
        return type(value) is int and 0 <= value < (1 << 64)

    def raw_site(snapshot, name):
        child = snapshot.get("sql_commit") if isinstance(snapshot, dict) else None
        rows = child.get("sites") if isinstance(child, dict) else None
        if not isinstance(rows, list) or len(rows) != len(sites):
            return None
        matches = [row for row in rows if isinstance(row, dict) and row.get("site") == name]
        return matches[0] if len(matches) == 1 else None

    def snapshot_rows(snapshot, side):
        need(isinstance(snapshot, dict), side + ":snapshot_missing_or_null")
        need(snapshot.get("schema") == "pon-native-history-arithmetic-observation-v1",
             side + ":snapshot_schema")
        need(snapshot.get("has_consensus_authority") is False, side + ":snapshot_authority")
        child = snapshot.get("sql_commit")
        need(isinstance(child, dict), side + ":sql_child_missing_or_null")
        need(child.get("schema") == "pon-native-sql-commit-call-observation-v1",
             side + ":sql_schema")
        need(child.get("observation_failed") is False, side + ":observation_failed_or_missing")
        need(child.get("has_consensus_authority") is False, side + ":sql_authority")
        rows = child.get("sites")
        need(isinstance(rows, list) and len(rows) == len(sites), side + ":sites_missing_or_count")
        names = [row.get("site") if isinstance(row, dict) else None for row in rows]
        need(all(type(name) is str and name in sites for name in names)
             and len(set(names)) == len(sites), side + ":site_identity")
        # The original stage_observation_failed flag belongs to a separate observer.
        return {row["site"]: row for row in rows}

    def totals(row, side):
        value = row.get("totals")
        need(isinstance(value, dict) and set(value) == set(counters + timings),
             side + ":totals_fields")
        need(all(uint(value[key]) for key in counters), side + ":counter_not_u64")
        need(all(value[key] is None or uint(value[key]) for key in timings),
             side + ":timing_not_nullable_u64")
        flight = row.get("calls_in_flight")
        need(uint(flight), side + ":in_flight_not_u64")
        ended = value["calls_returned"] + value["calls_abandoned"]
        need(value["calls_returned"] == value["calls_succeeded"] + value["calls_failed"]
             and value["calls_started"] == ended + flight
             and value["cpu_known_calls"] + value["cpu_unknown_calls"] == ended
             and value["wall_unknown_calls"] <= ended
             and value["calls_unwinding"] <= ended, side + ":call_accounting")
        need(value["cpu_known_calls"] > 0 or value["cpu_ns_known_sum"] == 0,
             side + ":cpu_sum_without_known_calls")
        if ended == 0:
            need(all(value[key] == 0 for key in counters if key != "calls_started")
                 and all(value[key] is None for key in timings), side + ":nonempty_unended_totals")
        else:
            need((value["wall_ns"] is None) == (value["wall_unknown_calls"] > 0),
                 side + ":wall_availability")
            need((value["cpu_ns"] is None) == (value["cpu_unknown_calls"] > 0),
                 side + ":cpu_availability")
            if value["cpu_ns"] is not None:
                need(value["cpu_ns"] == value["cpu_ns_known_sum"], side + ":cpu_complete_sum")
        return value, ended, flight

    global_error = None
    try:
        before_rows = snapshot_rows(before_snapshot, "before")
        after_rows = snapshot_rows(after_snapshot, "after")
    except ValueError as error:
        global_error = str(error)

    for name in sites:
        row = {
            "site": name, "before": raw_site(before_snapshot, name),
            "after": raw_site(after_snapshot, name), "status": "unknown",
            "reason": global_error, "cohort": None, "delta": None,
            "complete_wall_ns": None, "complete_cpu_ns": None,
            "wall_reason": global_error, "cpu_reason": global_error,
        }
        result["sites"].append(row)
        if global_error is not None:
            continue
        try:
            before, before_ended, before_flight = totals(before_rows[name], "before")
            after, after_ended, after_flight = totals(after_rows[name], "after")
            delta = {key: after[key] - before[key] for key in counters}
            need(all(value >= 0 for value in delta.values()), "cumulative_counter_regressed")
            ended = after_ended - before_ended
            flight_change = after_flight - before_flight  # A gauge may decrease.
            need(delta["calls_returned"] == delta["calls_succeeded"] + delta["calls_failed"]
                 and delta["calls_started"] == ended + flight_change
                 and delta["cpu_known_calls"] + delta["cpu_unknown_calls"] == ended
                 and delta["wall_unknown_calls"] <= ended
                 and delta["calls_unwinding"] <= ended, "delta_call_accounting")
            need(delta["cpu_known_calls"] > 0 or delta["cpu_ns_known_sum"] == 0,
                 "delta_cpu_sum_without_known_calls")
            wall = None
            if before["wall_ns"] is not None and after["wall_ns"] is not None:
                wall = after["wall_ns"] - before["wall_ns"]
                need(wall >= 0, "cumulative_wall_regressed")
            elif before["calls_started"] == 0 and after["wall_ns"] is not None:
                # totals() already proved a fully empty, null-timed baseline.
                wall = after["wall_ns"]
            need(ended > 0 or wall in (None, 0), "wall_changed_without_completed_call")
            delta.update({"ended_calls": ended, "calls_in_flight": flight_change,
                          "wall_ns": wall if ended > 0 else None})
            closed = before_flight == 0 and after_flight == 0
            status = "boundary" if not closed else ("observed" if ended else "unentered")
            wall_reason = ("boundary" if not closed else "unentered" if not ended
                           else "cumulative_wall_unknown" if wall is None else None)
            cpu_reason = ("boundary" if not closed else "unentered" if not ended
                          else "new_cpu_unknown_calls" if delta["cpu_unknown_calls"] else None)
            row.update({
                "status": status, "reason": None, "cohort": "closed" if closed else "boundary",
                "delta": delta,
                "complete_wall_ns": wall if wall_reason is None else None,
                "complete_cpu_ns": delta["cpu_ns_known_sum"] if cpu_reason is None else None,
                "wall_reason": wall_reason, "cpu_reason": cpu_reason,
            })
        except ValueError as error:
            row.update({"reason": str(error), "wall_reason": str(error), "cpu_reason": str(error)})
    unknown = sum(row["status"] == "unknown" for row in result["sites"])
    result["status"] = "unknown" if unknown == len(sites) else "partial_unknown" if unknown else "observed"
    return result


def sql_commit_delta_selfcheck():
    """Synthetic reader checks only; never executes native code or grants acceptance."""
    from copy import deepcopy

    names = ("admission_persistence", "atomic", "reorg_step", "reorg_termination")
    def empty():
        row = dict(calls_started=0, calls_returned=0, calls_succeeded=0, calls_failed=0,
                   calls_abandoned=0, calls_unwinding=0, wall_ns=None, cpu_ns=None,
                   cpu_ns_known_sum=0, wall_unknown_calls=0, cpu_known_calls=0, cpu_unknown_calls=0)
        return {"schema": "pon-native-history-arithmetic-observation-v1",
                "has_consensus_authority": False,
                "sql_commit": {"schema": "pon-native-sql-commit-call-observation-v1",
                               "observation_failed": False, "has_consensus_authority": False,
                               "sites": [{"site": name, "totals": deepcopy(row), "calls_in_flight": 0}
                                         for name in names]}}

    def sample(count, wall, cpu, *, cpu_unknown=0, wall_unknown=0, in_flight=0):
        value = empty()
        slot = value["sql_commit"]["sites"][0]
        slot["calls_in_flight"] = in_flight
        slot["totals"].update(calls_started=count + in_flight, calls_returned=count,
                             calls_succeeded=count, wall_ns=wall,
                             cpu_ns=None if cpu_unknown or count == 0 else cpu,
                             cpu_ns_known_sum=cpu, wall_unknown_calls=wall_unknown,
                             cpu_known_calls=count - cpu_unknown, cpu_unknown_calls=cpu_unknown)
        return value

    checked = []
    def check(condition, name):
        if not condition:
            raise AssertionError("SQL_COMMIT_DELTA_SELF_CHECK:" + name)
        checked.append(name)

    old = empty()
    del old["sql_commit"]
    check(sql_commit_delta(old, empty())["status"] == "unknown", "legacy_child_missing")
    check(sql_commit_delta(None, empty())["status"] == "unknown", "null_snapshot")
    a, b = empty(), sample(1, 100, 20)
    originals = deepcopy((a, b))
    result = sql_commit_delta(a, b)
    row = result["sites"][0]
    check(row["status"] == "observed" and row["cohort"] == "closed"
          and row["complete_wall_ns"] == 100 and row["complete_cpu_ns"] == 20
          and row["delta"]["calls_succeeded"] == 1
          and (a, b) == originals and row["before"] == a["sql_commit"]["sites"][0]
          and row["after"] == b["sql_commit"]["sites"][0], "empty_to_success_and_raw_preserved")
    check(all(row["status"] == "unentered" and row["complete_wall_ns"] is None
              and row["complete_cpu_ns"] is None for row in result["sites"][1:]), "unentered_not_zero")
    row = sql_commit_delta(sample(1, 100, 0, cpu_unknown=1),
                           sample(2, 180, 15, cpu_unknown=1))["sites"][0]
    check(row["complete_cpu_ns"] == 15 and row["complete_wall_ns"] == 80
          and row["before"]["totals"]["cpu_ns"] is None
          and row["after"]["totals"]["cpu_ns"] is None, "prior_cpu_unknown_new_window_known")
    row = sql_commit_delta(empty(), sample(2, 100, 15, cpu_unknown=1))["sites"][0]
    check(row["complete_cpu_ns"] is None and row["delta"]["cpu_ns_known_sum"] == 15
          and row["cpu_reason"] == "new_cpu_unknown_calls", "new_cpu_unknown_keeps_subtotal")
    row = sql_commit_delta(sample(1, None, 4, wall_unknown=1),
                           sample(2, None, 10, wall_unknown=1))["sites"][0]
    check(row["complete_wall_ns"] is None and row["wall_reason"] == "cumulative_wall_unknown"
          and row["complete_cpu_ns"] == 6, "wall_sticky_unknown")
    row = sql_commit_delta(sample(1, 100, 20, in_flight=1), sample(2, 180, 40))["sites"][0]
    check(row["status"] == "boundary" and row["delta"]["calls_in_flight"] == -1
          and row["delta"]["calls_started"] == 0 and row["delta"]["ended_calls"] == 1
          and row["complete_wall_ns"] is None and row["complete_cpu_ns"] is None,
          "boundary_gauge_decreases")
    bad = sample(1, 100, 20)
    bad["sql_commit"]["observation_failed"] = True
    check(sql_commit_delta(empty(), bad)["status"] == "unknown", "sticky_observation_failed")
    check(sql_commit_delta(sample(2, 180, 40), sample(1, 100, 20))["sites"][0]["status"]
          == "unknown", "counter_regression")
    for field, value, name in (("calls_returned", 2, "arithmetic_mismatch"),
                               ("calls_started", True, "bool_counter"),
                               ("wall_ns", True, "bool_duration")):
        bad = sample(1, 100, 20)
        bad["sql_commit"]["sites"][0]["totals"][field] = value
        check(sql_commit_delta(empty(), bad)["sites"][0]["status"] == "unknown", name)
    check(sql_commit_delta(sample(1, 100, 20), sample(2, 90, 40))["sites"][0]["status"]
          == "unknown", "wall_regression")
    bad = empty()
    bad["sql_commit"]["sites"][0]["totals"]["cpu_ns_known_sum"] = 1
    check(sql_commit_delta(bad, sample(1, 100, 20))["sites"][0]["status"]
          == "unknown", "nonempty_empty_baseline")
    bad = empty()
    bad["sql_commit"]["sites"][1]["site"] = names[0]
    check(sql_commit_delta(empty(), bad)["status"] == "unknown", "duplicate_site")
    row_source = sample(3, 60, 12)
    row_source["sql_commit"]["sites"][0]["totals"].update(
        calls_returned=2, calls_succeeded=1, calls_failed=1, calls_abandoned=1, calls_unwinding=1)
    row = sql_commit_delta(empty(), row_source)["sites"][0]
    check(row["status"] == "observed" and row["delta"]["calls_failed"] == 1
          and row["delta"]["calls_abandoned"] == 1 and row["delta"]["calls_unwinding"] == 1
          and row["complete_cpu_ns"] == 12, "failed_and_abandoned_preserved")
    return {"schema": "pon-native-sql-commit-delta-reader-selfcheck-v1",
            "passed": len(checked), "checks": checked,
            "source_tests_executed": False, "acceptance_granted": False}
