from __future__ import annotations

import email.utils
import hashlib
import hmac
import secrets
import threading
import typing
import unicodedata
from collections import OrderedDict
from urllib.parse import quote
from urllib.request import parse_http_list, parse_keqv_list

from urllib3._collections import HTTPHeaderDict
from urllib3.exceptions import ProtocolError
from urllib3.poolmanager import PoolManager
from urllib3.response import BaseHTTPResponse
from urllib3.util.request import set_file_position
from urllib3.util.url import parse_url

__all__ = ['DigestPoolManager']

_HASH_NAME_BY_ALGORITHM = {
    'MD5': 'md5',
    'SHA-256': 'sha256',
    'SHA-512-256': 'sha512_256',
}
_ALGORITHM_SUFFIX = '-SESS'
_QOP_AUTH = 'auth'
_QOP_AUTH_INT = 'auth-int'
_CHALLENGE_HEADER = 'WWW-Authenticate'
_AUTHENTICATION_INFO_HEADER = 'Authentication-Info'
_AUTHORIZATION_HEADER = 'Authorization'
_RETRY_MARKER = '_digest_auth_tried'
_CHALLENGE_MARKER = '_digest_auth_challenge'
_QUOTED_AUTH_FIELDS = frozenset(
    ['username', 'realm', 'nonce', 'uri', 'response', 'cnonce', 'opaque']
)
_DEFAULT_NONCE_CACHE_SIZE = 512
_TYPE_ORIGIN = tuple[str | None, str | None, int | None]
_TYPE_CHALLENGE_KEY = tuple[_TYPE_ORIGIN, str, str]
_TYPE_BODY_TO_HASH = str | bytes | bytearray | memoryview | None


class _DigestChallenge(typing.NamedTuple):
    params: dict[str, str]
    algorithm: str
    hash_name: str
    qop: str | None


def _quote_header_value(value: str) -> str:
    return f'"{email.utils.quote(value)}"'


def _parse_digest_challenges(
    header_values: typing.Iterable[str],
) -> list[dict[str, str]]:
    challenges = []

    for header_value in header_values:
        scheme = None
        param_parts: list[str] = []

        for part in parse_http_list(header_value):
            if ' ' in part:
                possible_scheme, rest = part.split(None, 1)
            else:
                possible_scheme, rest = part, ''

            if '=' not in possible_scheme:
                if scheme is not None:
                    challenges.append((scheme, param_parts))
                scheme = possible_scheme
                param_parts = [rest] if rest else []
            elif scheme is not None:
                param_parts.append(part)

        if scheme is not None:
            challenges.append((scheme, param_parts))

    digest_challenges = []
    for scheme, param_parts in challenges:
        if scheme.lower() != 'digest':
            continue

        digest_challenges.append(
            {key.lower(): value for key, value in parse_keqv_list(param_parts).items()}
        )

    return digest_challenges


def _parse_header_parameters(header_values: typing.Iterable[str]) -> dict[str, str]:
    params = {}
    for header_value in header_values:
        params.update(
            {
                key.lower(): value
                for key, value in parse_keqv_list(parse_http_list(header_value)).items()
            }
        )
    return params


def _choose_digest_challenge(
    header_values: typing.Iterable[str],
) -> _DigestChallenge | None:
    for params in _parse_digest_challenges(header_values):
        if 'realm' not in params or 'nonce' not in params:
            continue

        algorithm = params.get('algorithm', 'MD5')
        normalized_algorithm = algorithm.upper()
        if normalized_algorithm.endswith(_ALGORITHM_SUFFIX):
            hash_algorithm = normalized_algorithm[: -len(_ALGORITHM_SUFFIX)]
        else:
            hash_algorithm = normalized_algorithm

        hash_name = _HASH_NAME_BY_ALGORITHM.get(hash_algorithm)
        if hash_name is None or not _hash_supported(hash_name):
            continue

        qop = None
        if 'qop' in params:
            qop_tokens = {token.strip().lower() for token in params['qop'].split(',')}
            if _QOP_AUTH in qop_tokens:
                qop = _QOP_AUTH
            elif _QOP_AUTH_INT in qop_tokens:
                qop = _QOP_AUTH_INT
            else:
                continue

        return _DigestChallenge(params, algorithm, hash_name, qop)

    return None


def _format_digest_authorization(fields: typing.Mapping[str, str]) -> str:
    return 'Digest ' + ', '.join(
        f'{key}={_quote_header_value(value) if key in _QUOTED_AUTH_FIELDS else value}'
        for key, value in fields.items()
    )


def _build_digest_authorization(
    challenge: _DigestChallenge,
    method: str,
    uri: str,
    username: str,
    password: str,
    nonce_count: int,
    cnonce: str,
    body: object | None = None,
) -> str:
    params = challenge.params
    username = unicodedata.normalize('NFC', username)
    password = unicodedata.normalize('NFC', password)
    realm = params['realm']
    nonce = params['nonce']
    algorithm = challenge.algorithm
    hash_name = challenge.hash_name
    qop = challenge.qop
    nc_value = f'{nonce_count:08x}'
    encoding = (
        'utf-8'
        if params.get('charset', '').lower() == 'utf-8'
        or not username.isascii()
        or not password.isascii()
        else 'latin-1'
    )

    a1 = f'{username}:{realm}:{password}'
    ha1 = _hash(a1, hash_name, encoding)
    if algorithm.upper().endswith(_ALGORITHM_SUFFIX):
        ha1 = _hash(f'{ha1}:{nonce}:{cnonce}', hash_name, encoding)

    if qop == _QOP_AUTH_INT:
        ha2 = _hash(
            f'{method}:{uri}:{_hash_body(body, hash_name)}', hash_name, encoding
        )
    else:
        ha2 = _hash(f'{method}:{uri}', hash_name, encoding)
    if qop is None:
        response = _hash(f'{ha1}:{nonce}:{ha2}', hash_name, encoding)
    else:
        response = _hash(
            f'{ha1}:{nonce}:{nc_value}:{cnonce}:{qop}:{ha2}', hash_name, encoding
        )

    use_userhash = params.get('userhash', '').lower() == 'true'
    if use_userhash:
        username = _hash(f'{username}:{realm}', hash_name, encoding)
        username_field = 'username'
    elif not username.isascii():
        username = "UTF-8''" + quote(username, safe='', encoding='utf-8')
        username_field = 'username*'
    else:
        username_field = 'username'

    fields = {
        username_field: username,
        'realm': realm,
        'nonce': nonce,
        'uri': uri,
        'response': response,
        'algorithm': algorithm,
    }
    if 'opaque' in params:
        fields['opaque'] = params['opaque']
    if qop is not None:
        fields['qop'] = qop
        fields['nc'] = nc_value
        fields['cnonce'] = cnonce
    if use_userhash:
        fields['userhash'] = 'true'

    return _format_digest_authorization(fields)


def _expected_rspauth(
    authorization_params: typing.Mapping[str, str],
    username: str,
    password: str,
    response_body: _TYPE_BODY_TO_HASH = None,
    challenge: _DigestChallenge | None = None,
) -> str | None:
    realm = authorization_params.get('realm')
    nonce = authorization_params.get('nonce')
    uri = authorization_params.get('uri')
    cnonce = authorization_params.get('cnonce')
    response_qop = authorization_params.get('qop')
    nc_value = authorization_params.get('nc')
    if realm is None or nonce is None or uri is None:
        return None
    if response_qop is not None and (cnonce is None or nc_value is None):
        return None

    algorithm = authorization_params.get('algorithm', 'MD5')
    normalized_algorithm = algorithm.upper()
    if normalized_algorithm.endswith(_ALGORITHM_SUFFIX):
        hash_algorithm = normalized_algorithm[: -len(_ALGORITHM_SUFFIX)]
    else:
        hash_algorithm = normalized_algorithm

    hash_name = _HASH_NAME_BY_ALGORITHM.get(hash_algorithm)
    if hash_name is None:
        return None

    username = unicodedata.normalize('NFC', username)
    password = unicodedata.normalize('NFC', password)
    encoding = (
        'utf-8'
        if (
            challenge is not None
            and challenge.params.get('charset', '').lower() == 'utf-8'
        )
        or not username.isascii()
        or not password.isascii()
        else 'latin-1'
    )
    a1 = f'{username}:{realm}:{password}'
    ha1 = _hash(a1, hash_name, encoding)
    if normalized_algorithm.endswith(_ALGORITHM_SUFFIX):
        if cnonce is None:
            return None
        ha1 = _hash(f'{ha1}:{nonce}:{cnonce}', hash_name, encoding)

    if response_qop == _QOP_AUTH_INT:
        ha2 = _hash(
            f':{uri}:{_hash_body(response_body, hash_name)}', hash_name, encoding
        )
    else:
        ha2 = _hash(f':{uri}', hash_name, encoding)

    if response_qop is None:
        return _hash(f'{ha1}:{nonce}:{ha2}', hash_name, encoding)
    return _hash(
        f'{ha1}:{nonce}:{nc_value}:{cnonce}:{response_qop}:{ha2}',
        hash_name,
        encoding,
    )


def _hash(data: str | bytes, hash_name: str, encoding: str = 'latin-1') -> str:
    if isinstance(data, str):
        data = data.encode(encoding)
    return hashlib.new(hash_name, data, usedforsecurity=False).hexdigest()


def _hash_supported(hash_name: str) -> bool:
    try:
        hashlib.new(hash_name, usedforsecurity=False)
    except ValueError:
        return False
    return True


def _hash_body(body: object | None, hash_name: str) -> str:
    if body is None:
        body = b''
    if isinstance(body, str):
        body = body.encode('utf-8')

    digest = hashlib.new(hash_name, usedforsecurity=False)
    try:
        digest.update(memoryview(body))  # type: ignore[arg-type]
    except TypeError:
        raise ValueError(
            "qop='auth-int' requires a bytes-like, str, or empty request body"
        ) from None
    return digest.hexdigest()


class DigestPoolManager(PoolManager):
    """
    A :class:`~urllib3.PoolManager` that responds to HTTP Digest challenges.

    ``DigestPoolManager`` sends the first request without credentials. If the
    server returns a usable ``WWW-Authenticate: Digest`` challenge, it drains
    that response and retries once with an ``Authorization`` header.
    """

    def __init__(
        self,
        username: str,
        password: str,
        num_pools: int = 10,
        headers: typing.Mapping[str, str] | None = None,
        digest_cache_size: int = _DEFAULT_NONCE_CACHE_SIZE,
        **connection_pool_kw: typing.Any,
    ) -> None:
        super().__init__(num_pools=num_pools, headers=headers, **connection_pool_kw)
        self.username = username
        self.password = password
        self._digest_cache_size = max(0, digest_cache_size)
        self._nonce_counts: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._challenges: OrderedDict[_TYPE_CHALLENGE_KEY, _DigestChallenge] = (
            OrderedDict()
        )
        self._digest_lock = threading.Lock()

    def urlopen(  # type: ignore[override]
        self, method: str, url: str, redirect: bool = True, **kw: typing.Any
    ) -> BaseHTTPResponse:
        digest_auth_tried = kw.pop(_RETRY_MARKER, False)
        request_challenge = kw.pop(_CHALLENGE_MARKER, None)
        if 'body' in kw and 'body_pos' not in kw:
            kw = kw.copy()
            kw['body_pos'] = set_file_position(kw['body'], None)

        if not digest_auth_tried and not self._has_authorization_header(kw):
            challenge = self._challenge_for_url(url)
            if challenge is not None:
                try:
                    kw = self._with_authorization(kw, challenge, method, url)
                    request_challenge = challenge
                except ValueError:
                    pass

        response = super().urlopen(method, url, redirect=redirect, **kw)

        if response.status != 401:
            self._validate_rspauth(
                response, kw.get('headers'), kw.get('body'), request_challenge
            )
            self._update_challenge_from_authentication_info(url, response)
            return response

        if digest_auth_tried:
            return response

        header_values = response.headers.getlist(_CHALLENGE_HEADER)
        challenge = _choose_digest_challenge(header_values)
        if challenge is None:
            return response

        try:
            kw = self._with_authorization(kw, challenge, method, url)
        except ValueError:
            return response

        response.drain_conn()
        kw[_RETRY_MARKER] = True
        kw[_CHALLENGE_MARKER] = challenge
        response = self.urlopen(method, url, redirect=redirect, **kw)
        if response.status != 401:
            self._store_challenge(url, challenge, response)
        return response

    def _has_authorization_header(self, kw: dict[str, typing.Any]) -> bool:
        headers = kw.get('headers') or self.headers or {}
        return any(header.lower() == 'authorization' for header in headers)

    def _with_authorization(
        self,
        kw: dict[str, typing.Any],
        challenge: _DigestChallenge,
        method: str,
        url: str,
    ) -> dict[str, typing.Any]:
        headers = HTTPHeaderDict(kw.get('headers', self.headers))
        headers[_AUTHORIZATION_HEADER] = self._authorization_header(
            challenge, method, url, kw.get('body')
        )
        kw = kw.copy()
        kw['headers'] = headers
        return kw

    def _authorization_header(
        self,
        challenge: _DigestChallenge,
        method: str,
        url: str,
        body: object | None = None,
    ) -> str:
        uri = parse_url(url).request_uri
        cnonce = secrets.token_hex(16)
        nonce_count = self._allocate_nonce_count(challenge)
        return _build_digest_authorization(
            challenge,
            method,
            uri,
            self.username,
            self.password,
            nonce_count,
            cnonce,
            body,
        )

    def _allocate_nonce_count(self, challenge: _DigestChallenge) -> int:
        key = (challenge.params['realm'], challenge.params['nonce'])
        with self._digest_lock:
            nonce_count = self._nonce_counts.get(key, 0) + 1
            if key in self._nonce_counts:
                self._nonce_counts.move_to_end(key)
            self._nonce_counts[key] = nonce_count
            self._evict_lru(self._nonce_counts)
            return nonce_count

    def _challenge_for_url(self, url: str) -> _DigestChallenge | None:
        origin = self._origin_key(url)
        request_uri = parse_url(url).request_uri
        with self._digest_lock:
            key = self._challenge_key_for_url_unlocked(origin, request_uri)
            if key is None:
                return None

            self._challenges.move_to_end(key)
            return self._copy_challenge(self._challenges[key])

    def _store_challenge(
        self,
        url: str,
        challenge: _DigestChallenge,
        response: BaseHTTPResponse | None = None,
    ) -> None:
        challenge = self._copy_challenge(challenge)
        if response is not None:
            params = _parse_header_parameters(
                response.headers.getlist(_AUTHENTICATION_INFO_HEADER)
            )
            nextnonce = params.get('nextnonce')
            if nextnonce is not None:
                challenge_params = challenge.params.copy()
                challenge_params['nonce'] = nextnonce
                challenge = _DigestChallenge(
                    challenge_params,
                    challenge.algorithm,
                    challenge.hash_name,
                    challenge.qop,
                )

        keys = [
            (self._origin_key(url), challenge.params['realm'], prefix)
            for prefix in self._protection_space_prefixes(url, challenge)
        ]
        with self._digest_lock:
            for key in keys:
                if key in self._challenges:
                    self._challenges.move_to_end(key)
                self._challenges[key] = self._copy_challenge(challenge)
            self._evict_lru(self._challenges)

    def _update_challenge_from_authentication_info(
        self, url: str, response: BaseHTTPResponse
    ) -> None:
        params = _parse_header_parameters(
            response.headers.getlist(_AUTHENTICATION_INFO_HEADER)
        )
        nextnonce = params.get('nextnonce')
        if nextnonce is None:
            return

        origin = self._origin_key(url)
        request_uri = parse_url(url).request_uri

        with self._digest_lock:
            key = self._challenge_key_for_url_unlocked(origin, request_uri)
            if key is None:
                return

            state = self._challenges.get(key)
            if state is None:
                return

            old_nonce = state.params['nonce']
            updates = [
                (other_key, other_state)
                for other_key, other_state in self._challenges.items()
                if other_key[0] == key[0]
                and other_state.params.get('realm') == state.params['realm']
                and other_state.params.get('nonce') == old_nonce
            ]

            for update_key, update_state in updates:
                self._challenges.move_to_end(update_key)
                challenge_params = update_state.params.copy()
                challenge_params['nonce'] = nextnonce
                self._challenges[update_key] = _DigestChallenge(
                    challenge_params,
                    update_state.algorithm,
                    update_state.hash_name,
                    update_state.qop,
                )
            self._evict_lru(self._challenges)

    def _origin_key(self, url: str) -> tuple[str | None, str | None, int | None]:
        parsed_url = parse_url(url)
        return parsed_url.scheme, parsed_url.host, parsed_url.port

    def _challenge_key_for_url_unlocked(
        self, origin: _TYPE_ORIGIN, request_uri: str
    ) -> _TYPE_CHALLENGE_KEY | None:
        matches = [
            key
            for key in self._challenges
            if key[0] == origin and request_uri.startswith(key[2])
        ]
        if not matches:
            return None
        return max(matches, key=lambda match: len(match[2]))

    def _copy_challenge(self, challenge: _DigestChallenge) -> _DigestChallenge:
        return _DigestChallenge(
            challenge.params.copy(),
            challenge.algorithm,
            challenge.hash_name,
            challenge.qop,
        )

    def _protection_space_prefixes(
        self, url: str, challenge: _DigestChallenge
    ) -> list[str]:
        domain = challenge.params.get('domain')
        if not domain:
            return ['/']

        origin = self._origin_key(url)
        prefixes = []
        for item in domain.split():
            parsed_item = parse_url(item)
            if (
                parsed_item.host is not None
                and (
                    parsed_item.scheme,
                    parsed_item.host,
                    parsed_item.port,
                )
                != origin
            ):
                continue
            prefixes.append(parsed_item.request_uri)
        return prefixes or ['/']

    def _validate_rspauth(
        self,
        response: BaseHTTPResponse,
        headers: typing.Mapping[str, str] | None,
        body: object | None,
        challenge: _DigestChallenge | None,
    ) -> None:
        auth_info = _parse_header_parameters(
            response.headers.getlist(_AUTHENTICATION_INFO_HEADER)
        )
        if not auth_info or headers is None:
            return

        authorization = HTTPHeaderDict(headers).get(_AUTHORIZATION_HEADER)
        if authorization is None:
            return

        authorization_challenges = _parse_digest_challenges([authorization])
        if not authorization_challenges:
            return

        authorization_params = authorization_challenges[0]
        rspauth = auth_info.get('rspauth')
        if authorization_params.get('qop') is not None and rspauth is None:
            raise ProtocolError('Digest authentication response was incomplete')
        if rspauth is None:
            return

        response_body = None
        if authorization_params.get('qop') == _QOP_AUTH_INT:
            response_body = getattr(response, '_body', None)
            if response_body is None:
                raise ProtocolError(
                    'Digest auth-int server response cannot be validated before '
                    'the response body is read'
                )

        expected_rspauth = _expected_rspauth(
            authorization_params, self.username, self.password, response_body, challenge
        )
        if expected_rspauth is not None and not hmac.compare_digest(
            rspauth, expected_rspauth
        ):
            raise ProtocolError('Digest authentication server response was invalid')

    def _evict_lru(self, cache: OrderedDict[typing.Any, typing.Any]) -> None:
        while len(cache) > self._digest_cache_size:
            cache.popitem(last=False)
