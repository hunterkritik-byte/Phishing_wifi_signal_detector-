from wifi_safety.jamming_detection import assess_interference


def test_noise_spike_is_flagged_without_claiming_jamming():
    observations = [{"noise_dbm": -90, "beacon_count": 100} for _ in range(6)]
    observations += [{"noise_dbm": -75, "beacon_count": 100} for _ in range(6)]
    finding = assess_interference(observations)
    assert finding.score >= 25
    assert finding.level in {"review", "high-concern"}
    assert "jamming" not in " ".join(finding.reasons).lower()


def test_beacon_drop_is_flagged():
    observations = [{"beacon_count": 100} for _ in range(6)]
    observations += [{"beacon_count": 20} for _ in range(6)]
    finding = assess_interference(observations)
    assert finding.score >= 30
