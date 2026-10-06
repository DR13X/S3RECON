from s3recon.config.schema import Config, ScopeConfig

def test_scope_bucket():
    scope = ScopeConfig(buckets=["my-bucket"])
    assert scope.is_target_allowed("my-bucket")
    assert not scope.is_target_allowed("other")

def test_scope_domain():
    scope = ScopeConfig(domains=["example.com"])
    assert scope.is_target_allowed("example")
    assert scope.is_target_allowed("example-backup")

def test_defaults():
    cfg = Config()
    assert cfg.safety.metadata_only is True
    assert cfg.safety.destructive_operations is False
    assert cfg.safety.download_content is False
