from s3recon.models.findings import (
    DEFAULT_REMEDIATIONS, Evidence, ExposureType, Finding, Provider, RiskLevel, ScanResult,
)

def test_finding_to_dict():
    f = Finding(
        target="test-bucket", provider=Provider.AWS_S3,
        finding_type=ExposureType.PUBLIC_LISTABLE, risk_level=RiskLevel.MEDIUM,
        evidence=Evidence(status_code=200), remediation="Restrict listing",
    )
    d = f.to_dict()
    assert d["target"] == "test-bucket"
    assert d["provider"] == "s3"
    assert d["risk_level"] == "medium"

def test_scan_summary():
    findings = [
        Finding(target="a", provider=Provider.AWS_S3, finding_type=ExposureType.PUBLIC_READABLE,
                risk_level=RiskLevel.HIGH, evidence=Evidence()),
        Finding(target="b", provider=Provider.GCP_STORAGE, finding_type=ExposureType.NON_EXISTENT,
                risk_level=RiskLevel.INFORMATIONAL, evidence=Evidence()),
    ]
    sr = ScanResult(scan_id="x", started_at="now", findings=findings, targets_tested=2)
    s = sr.summary()
    assert s["high"] == 1
    assert s["informational"] == 1
    assert s["total_findings"] == 2

def test_remediations_complete():
    for et in ExposureType:
        assert et in DEFAULT_REMEDIATIONS
