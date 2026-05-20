## digestauth3

This library provides `DigestPoolManager`, a `urllib3.PoolManager` subclass that 
supports [HTTP Digest Access Authentication](https://datatracker.ietf.org/doc/html/rfc7616).

## Usage

```python3
from digestauth3 import DigestAuth, DigestPoolManager

http = DigestPoolManager()
digest_auth = DigestAuth('some-user', 'some-pw')
resp = http.request(
    'GET',
    'http://httpbin.org/digest-auth/some-bqop/some-user/some-pw',
    digest_auth=digest_auth,
)
print(resp.json())
# {'authenticated': True, 'user': 'some-user'}
```

## Status

This package is experimental, so don't use it in production workloads.
