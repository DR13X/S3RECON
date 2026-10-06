import pytest
import respx
from httpx import Response
from s3recon.config.schema import Config
from s3recon.models.findings import ExposureType
from s3recon.providers.aws_s3.provider import S3Provider

@pytest.fixture
def config():
    return Config()

@respx.mock
@pytest.mark.asyncio
async def test_s3_nonexistent(config):
    respx.get(url__regex=r"https://.*s3.*").mock(
        return_value=Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")
    )
    f = await S3Provider(config).check_existence("no-such-bucket-xyz")
    assert f.finding_type == ExposureType.NON_EXISTENT

@respx.mock
@pytest.mark.asyncio
async def test_s3_access_denied(config):
    respx.get(url__regex=r"https://.*s3.*").mock(return_value=Response(403, text="Access Denied"))
    f = await S3Provider(config).check_existence("private-bucket")
    assert f.finding_type == ExposureType.ACCESS_DENIED

@respx.mock
@pytest.mark.asyncio
async def test_s3_public_listable(config):
    xml = '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>pub</Name><Contents><Key>f.txt</Key><Size>1</Size></Contents></ListBucketResult>'
    respx.get(url__regex=r"https://.*s3.*").mock(return_value=Response(200, text=xml))
    f = await S3Provider(config).check_existence("public-bucket")
    assert f.finding_type == ExposureType.PUBLIC_LISTABLE
