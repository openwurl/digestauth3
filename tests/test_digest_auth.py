from __future__ import annotations

import concurrent.futures
import unicodedata
import unittest
from unittest import mock

from urllib3 import HTTPResponse
from urllib3.exceptions import ProtocolError

from digestauth3.digest_auth import (
    DigestPoolManager,
    _build_digest_authorization,
    _choose_digest_challenge,
    _expected_rspauth,
    _format_digest_authorization,
    _hash_body,
    _parse_digest_challenges,
)


class TestParseDigestChallenges(unittest.TestCase):
    def test_quoted_commas(self) -> None:
        challenges = _parse_digest_challenges(
            [
                'Basic realm="basic", Digest realm="digest, realm", '
                'nonce="n\\"once", qop="auth, auth-int", algorithm=SHA-256'
            ]
        )

        self.assertEqual(
            challenges,
            [
                {
                    'realm': 'digest, realm',
                    'nonce': 'n"once',
                    'qop': 'auth, auth-int',
                    'algorithm': 'SHA-256',
                }
            ],
        )


class TestChooseDigestChallenge(unittest.TestCase):
    def test_chooses_first_supported(self) -> None:
        challenge = _choose_digest_challenge(
            [
                'Digest realm="unsupported", nonce="n1", algorithm=unknown',
                'Digest realm="supported", nonce="n2", algorithm=SHA-256',
            ]
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.params['realm'], 'supported')
        self.assertEqual(challenge.hash_name, 'sha256')

    def test_uses_first_supported_algorithm(self) -> None:
        challenge = _choose_digest_challenge(
            [
                'Digest realm="preferred", nonce="n1", algorithm=SHA-256',
                'Digest realm="backup", nonce="n2", algorithm=SHA-512-256',
            ]
        )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.params['realm'], 'preferred')

    def test_ignores_unavailable_hash(self) -> None:
        real_new = __import__('hashlib').new

        def new(name: str, *args: object, **kwargs: object) -> object:
            if name == 'sha512_256':
                raise ValueError(name)
            return real_new(name, *args, **kwargs)

        with mock.patch('digestauth3.digest_auth.hashlib.new', new):
            challenge = _choose_digest_challenge(
                [
                    'Digest realm="unavailable", nonce="n1", algorithm=SHA-512-256',
                    'Digest realm="available", nonce="n2", algorithm=SHA-256',
                ]
            )

        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.params['realm'], 'available')


class TestBuildDigestAuthorization(unittest.TestCase):
    def test_preserves_challenge_algorithm_value(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth", algorithm=md5-sess']
        )

        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'user',
            'password',
            1,
            'client',
        )

        self.assertIn('algorithm=md5-sess', authorization)

    def test_supports_userhash(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth", userhash=true']
        )

        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'user',
            'password',
            1,
            'client',
        )

        params = _parse_digest_challenges([authorization])[0]
        self.assertEqual(params['username'], 'e760591138c3df8c9c11eeba43a9f851')
        self.assertEqual(params['userhash'], 'true')

    def test_uses_username_star_for_non_ascii(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth"']
        )

        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'Jäsøn',
            'password',
            1,
            'client',
        )

        params = _parse_digest_challenges([authorization])[0]
        self.assertNotIn('username', params)
        self.assertEqual(params['username*'], "UTF-8''J%C3%A4s%C3%B8n")

    def test_normalizes_username_and_password(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth", charset=UTF-8']
        )

        self.assertIsNotNone(challenge)
        composed = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'Jäsøn',
            'pässword',
            1,
            'client',
        )
        decomposed = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            unicodedata.normalize('NFD', 'Jäsøn'),
            unicodedata.normalize('NFD', 'pässword'),
            1,
            'client',
        )

        self.assertEqual(
            _parse_digest_challenges([composed])[0]['response'],
            _parse_digest_challenges([decomposed])[0]['response'],
        )

    def test_supports_auth_int(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth-int"']
        )

        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'POST',
            '/protected',
            'user',
            'password',
            1,
            'client',
            b'body',
        )
        other_authorization = _build_digest_authorization(
            challenge,
            'POST',
            '/protected',
            'user',
            'password',
            1,
            'client',
            b'other-body',
        )

        params = _parse_digest_challenges([authorization])[0]
        other_params = _parse_digest_challenges([other_authorization])[0]
        self.assertEqual(params['qop'], 'auth-int')
        self.assertNotEqual(params['response'], other_params['response'])

    def test_rfc_7616_md5_example_response(self) -> None:
        challenge = _choose_digest_challenge(
            [
                'Digest realm="http-auth@example.org", qop="auth, auth-int", '
                'algorithm=MD5, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
                'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
            ]
        )

        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/dir/index.html',
            'Mufasa',
            'Circle of Life',
            1,
            'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ',
        )

        self.assertIn('response="8ca523f5e9506fed4657c9700eebdbec"', authorization)

    def test_rfc_7616_sha256_example_response(self) -> None:
        challenge = _choose_digest_challenge(
            [
                'Digest realm="http-auth@example.org", qop="auth, auth-int", '
                'algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
                'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
            ]
        )

        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/dir/index.html',
            'Mufasa',
            'Circle of Life',
            1,
            'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ',
        )

        self.assertIn(
            'response="753927fa0e85d155564e2e272a28d1802ca10daf449'
            '6794697cf8db5856cb6c1"',
            authorization,
        )


class TestFormatDigestAuthorization(unittest.TestCase):
    def test_quotes_selected_fields(self) -> None:
        authorization = _format_digest_authorization(
            {
                'username': 'user"name',
                'realm': 'realm',
                'algorithm': 'MD5',
                'qop': 'auth',
                'nc': '00000001',
                'cnonce': 'client',
            }
        )

        self.assertEqual(
            authorization,
            'Digest username="user\\"name", realm="realm", algorithm=MD5, '
            'qop=auth, nc=00000001, cnonce="client"',
        )


class TestDigestPoolManager(unittest.TestCase):
    def test_retries_once_without_mutating_headers(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        authorized = HTTPResponse(status=200)
        headers = {'X-Test': 'value'}

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[unauthorized, authorized],
        ) as urlopen:
            response = DigestPoolManager('user', 'password').request(
                'GET', 'http://example.com/protected', headers=headers
            )

        self.assertIs(response, authorized)
        self.assertEqual(headers, {'X-Test': 'value'})
        self.assertEqual(urlopen.call_count, 2)

        retried_headers = urlopen.call_args_list[1].kwargs['headers']
        self.assertEqual(retried_headers['X-Test'], 'value')
        self.assertTrue(retried_headers['Authorization'].startswith('Digest '))

    def test_handles_explicit_none_headers(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        authorized = HTTPResponse(status=200)

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[unauthorized, authorized],
        ):
            response = DigestPoolManager('user', 'password').urlopen(
                'GET', 'http://example.com/protected', headers=None
            )

        self.assertIs(response, authorized)

    def test_does_not_retry_forever(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[unauthorized, unauthorized],
        ) as urlopen:
            response = DigestPoolManager('user', 'password').request(
                'GET', 'http://example.com/protected'
            )

        self.assertIs(response, unauthorized)
        self.assertEqual(urlopen.call_count, 2)

    def test_reuses_nextnonce_preemptively(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth"']
        )
        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'user',
            'password',
            1,
            'client',
        )
        params = _parse_digest_challenges([authorization])[0]
        rspauth = _expected_rspauth(params, 'user', 'password')
        authorized = HTTPResponse(
            status=200,
            headers={
                'Authentication-Info': f'rspauth="{rspauth}", nextnonce="next-nonce"'
            },
        )
        preemptive = HTTPResponse(status=200)

        with (
            mock.patch(
                'digestauth3.digest_auth.secrets.token_hex', return_value='client'
            ),
            mock.patch(
                'digestauth3.digest_auth.PoolManager.urlopen',
                side_effect=[unauthorized, authorized, preemptive],
            ) as urlopen,
        ):
            http = DigestPoolManager('user', 'password')
            self.assertIs(
                http.request('GET', 'http://example.com/protected'), authorized
            )
            self.assertIs(
                http.request('GET', 'http://example.com/protected'), preemptive
            )

        self.assertEqual(urlopen.call_count, 3)
        headers = urlopen.call_args_list[2].kwargs['headers']
        params = _parse_digest_challenges([headers['Authorization']])[0]
        self.assertEqual(params['nonce'], 'next-nonce')
        self.assertEqual(params['nc'], '00000001')

    def test_accepts_nextnonce_without_rspauth_for_legacy_qop(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={'WWW-Authenticate': 'Digest realm="realm", nonce="nonce"'},
        )
        authorized = HTTPResponse(
            status=200, headers={'Authentication-Info': 'nextnonce="next-nonce"'}
        )

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[unauthorized, authorized],
        ):
            response = DigestPoolManager('user', 'password').request(
                'GET', 'http://example.com/protected'
            )

        self.assertIs(response, authorized)

    def test_rejects_incomplete_authentication_info(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        authorized = HTTPResponse(
            status=200, headers={'Authentication-Info': 'nextnonce="next-nonce"'}
        )

        with (
            mock.patch(
                'digestauth3.digest_auth.secrets.token_hex', return_value='client'
            ),
            mock.patch(
                'digestauth3.digest_auth.PoolManager.urlopen',
                side_effect=[unauthorized, authorized],
            ),
        ):
            with self.assertRaises(ProtocolError):
                DigestPoolManager('user', 'password').request(
                    'GET', 'http://example.com/protected'
                )

    def test_updates_nextnonce_for_all_domain_prefixes(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="old", qop="auth", domain="/api /admin"']
        )
        self.assertIsNotNone(challenge)

        http = DigestPoolManager('user', 'password')
        http._store_challenge('http://example.com/api/resource', challenge)
        http._update_challenge_from_authentication_info(
            'http://example.com/api/resource',
            HTTPResponse(
                status=200, headers={'Authentication-Info': 'nextnonce="new"'}
            ),
        )

        self.assertEqual(
            {state.params['nonce'] for state in http._challenges.values()}, {'new'}
        )

    def test_caches_by_protection_space(self) -> None:
        api_unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': (
                    'Digest realm="api", nonce="api-nonce", qop="auth", domain="/api/"'
                )
            },
        )
        api_authorized = HTTPResponse(status=200)
        admin_unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': (
                    'Digest realm="admin", nonce="admin-nonce", qop="auth", '
                    'domain="/admin/"'
                )
            },
        )
        admin_authorized = HTTPResponse(status=200)
        api_preemptive = HTTPResponse(status=200)

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[
                api_unauthorized,
                api_authorized,
                admin_unauthorized,
                admin_authorized,
                api_preemptive,
            ],
        ) as urlopen:
            http = DigestPoolManager('user', 'password')
            http.request('GET', 'http://example.com/api/resource')
            http.request('GET', 'http://example.com/admin/resource')
            http.request('GET', 'http://example.com/api/other')

        self.assertEqual(urlopen.call_count, 5)
        self.assertNotIn('Authorization', urlopen.call_args_list[2].kwargs['headers'])
        preemptive_headers = urlopen.call_args_list[4].kwargs['headers']
        params = _parse_digest_challenges([preemptive_headers['Authorization']])[0]
        self.assertEqual(params['realm'], 'api')

    def test_uses_origin_scope_without_domain(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        authorized = HTTPResponse(status=200)
        preemptive = HTTPResponse(status=200)

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[unauthorized, authorized, preemptive],
        ) as urlopen:
            http = DigestPoolManager('user', 'password')
            http.request('GET', 'http://example.com/api/v1/users')
            http.request('GET', 'http://example.com/api/v2/data')

        self.assertEqual(urlopen.call_count, 3)
        headers = urlopen.call_args_list[2].kwargs['headers']
        self.assertTrue(headers['Authorization'].startswith('Digest '))

    def test_validates_rspauth(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth"']
        )
        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'user',
            'password',
            1,
            'client',
        )
        params = _parse_digest_challenges([authorization])[0]
        rspauth = _expected_rspauth(params, 'user', 'password')
        authorized = HTTPResponse(
            status=200, headers={'Authentication-Info': f'rspauth="{rspauth}"'}
        )

        with (
            mock.patch(
                'digestauth3.digest_auth.secrets.token_hex', return_value='client'
            ),
            mock.patch(
                'digestauth3.digest_auth.PoolManager.urlopen',
                side_effect=[unauthorized, authorized],
            ),
        ):
            response = DigestPoolManager('user', 'password').request(
                'GET', 'http://example.com/protected'
            )

        self.assertIs(response, authorized)

    def test_validates_rspauth_with_utf8_credentials(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': (
                    'Digest realm="realm", nonce="nonce", qop="auth", charset=UTF-8'
                )
            },
        )
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth", charset=UTF-8']
        )
        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'Jäsøn',
            'pässword',
            1,
            'client',
        )
        params = _parse_digest_challenges([authorization])[0]
        rspauth = _expected_rspauth(params, 'Jäsøn', 'pässword')
        authorized = HTTPResponse(
            status=200, headers={'Authentication-Info': f'rspauth="{rspauth}"'}
        )

        with (
            mock.patch(
                'digestauth3.digest_auth.secrets.token_hex', return_value='client'
            ),
            mock.patch(
                'digestauth3.digest_auth.PoolManager.urlopen',
                side_effect=[unauthorized, authorized],
            ),
        ):
            response = DigestPoolManager('Jäsøn', 'pässword').request(
                'GET', 'http://example.com/protected'
            )

        self.assertIs(response, authorized)

    def test_rejects_invalid_rspauth(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth"'
            },
        )
        authorized = HTTPResponse(
            status=200, headers={'Authentication-Info': 'rspauth="wrong"'}
        )

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            side_effect=[unauthorized, authorized],
        ):
            with self.assertRaises(ProtocolError):
                DigestPoolManager('user', 'password').request(
                    'GET', 'http://example.com/protected'
                )

    def test_validates_auth_int_rspauth_with_response_body(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth-int"'
            },
        )
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth-int"']
        )
        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge,
            'GET',
            '/protected',
            'user',
            'password',
            1,
            'client',
        )
        params = _parse_digest_challenges([authorization])[0]
        rspauth = _expected_rspauth(params, 'user', 'password', b'response')
        authorized = HTTPResponse(
            b'response',
            status=200,
            headers={'Authentication-Info': f'rspauth="{rspauth}"'},
        )

        with (
            mock.patch(
                'digestauth3.digest_auth.secrets.token_hex', return_value='client'
            ),
            mock.patch(
                'digestauth3.digest_auth.PoolManager.urlopen',
                side_effect=[unauthorized, authorized],
            ),
        ):
            response = DigestPoolManager('user', 'password').request(
                'GET', 'http://example.com/protected'
            )

        self.assertIs(response, authorized)

    def test_returns_401_for_auth_int_streaming_body(self) -> None:
        unauthorized = HTTPResponse(
            status=401,
            headers={
                'WWW-Authenticate': 'Digest realm="realm", nonce="nonce", qop="auth-int"'
            },
        )

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            return_value=unauthorized,
        ) as urlopen:
            response = DigestPoolManager('user', 'password').request(
                'POST',
                'http://example.com/protected',
                body=iter([b'body']),
            )

        self.assertIs(response, unauthorized)
        self.assertEqual(urlopen.call_count, 1)

    def test_nonce_counts_are_lru_bounded(self) -> None:
        http = DigestPoolManager('user', 'password', digest_cache_size=2)

        for nonce in ('one', 'two', 'three'):
            challenge = _choose_digest_challenge(
                [f'Digest realm="realm", nonce="{nonce}", qop="auth"']
            )
            self.assertIsNotNone(challenge)
            http._authorization_header(challenge, 'GET', 'http://example.com/protected')

        self.assertEqual(
            list(http._nonce_counts), [('realm', 'two'), ('realm', 'three')]
        )

    def test_nonce_counts_are_thread_safe(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth"']
        )
        self.assertIsNotNone(challenge)

        http = DigestPoolManager('user', 'password')

        def build_authorization(_: int) -> str:
            authorization = http._authorization_header(
                challenge, 'GET', 'http://example.com/protected'
            )
            return _parse_digest_challenges([authorization])[0]['nc']

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            nonce_counts = list(executor.map(build_authorization, range(50)))

        self.assertEqual(
            sorted(nonce_counts), [f'{index:08x}' for index in range(1, 51)]
        )


class TestChooseDigestChallengeEdgeCases(unittest.TestCase):
    def test_skips_challenge_missing_realm(self) -> None:
        # A challenge that has nonce but no realm is skipped (line 111), and when
        # there are no remaining candidates the function returns None (line 136).
        challenge = _choose_digest_challenge(
            ['Digest nonce="n", algorithm=MD5']
        )
        self.assertIsNone(challenge)

    def test_skips_challenge_missing_nonce(self) -> None:
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", algorithm=MD5']
        )
        self.assertIsNone(challenge)

    def test_skips_challenge_with_unrecognised_qop(self) -> None:
        # qop present but the only token is not "auth" or "auth-int" (line 132).
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="n", qop="custom"']
        )
        self.assertIsNone(challenge)

    def test_returns_first_supported_after_skipping_invalid(self) -> None:
        # Confirm the loop keeps going past skipped entries (line 111 continue).
        challenge = _choose_digest_challenge(
            [
                'Digest nonce="n1", algorithm=MD5',  # no realm – skipped
                'Digest realm="realm", nonce="n2", algorithm=MD5',
            ]
        )
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.params['nonce'], 'n2')


class TestExpectedRspauth(unittest.TestCase):
    def test_returns_none_for_missing_realm(self) -> None:
        # realm/nonce/uri are all required; missing any returns None (line 235).
        result = _expected_rspauth({'nonce': 'n', 'uri': '/'}, 'user', 'pass')
        self.assertIsNone(result)

    def test_returns_none_for_missing_nonce(self) -> None:
        result = _expected_rspauth({'realm': 'r', 'uri': '/'}, 'user', 'pass')
        self.assertIsNone(result)

    def test_returns_none_for_missing_uri(self) -> None:
        result = _expected_rspauth({'realm': 'r', 'nonce': 'n'}, 'user', 'pass')
        self.assertIsNone(result)

    def test_returns_none_for_qop_without_cnonce(self) -> None:
        # qop present but cnonce missing → None (line 237).
        params = {'realm': 'r', 'nonce': 'n', 'uri': '/', 'qop': 'auth', 'nc': '00000001'}
        result = _expected_rspauth(params, 'user', 'pass')
        self.assertIsNone(result)

    def test_returns_none_for_unknown_algorithm(self) -> None:
        # Hash name not in the supported map → None (line 248).
        params = {'realm': 'r', 'nonce': 'n', 'uri': '/', 'algorithm': 'BOGUS-256'}
        result = _expected_rspauth(params, 'user', 'pass')
        self.assertIsNone(result)

    def test_sess_algorithm_updates_ha1(self) -> None:
        # -SESS path: line 242 extracts base algorithm, line 267 rehashes ha1.
        params = {
            'realm': 'realm',
            'nonce': 'nonce',
            'uri': '/',
            'algorithm': 'MD5-SESS',
            'qop': 'auth',
            'nc': '00000001',
            'cnonce': 'client',
        }
        result = _expected_rspauth(params, 'user', 'password')
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)

    def test_sess_algorithm_without_cnonce_returns_none(self) -> None:
        # -SESS with no qop means cnonce is absent; line 265-266 returns None.
        params = {'realm': 'realm', 'nonce': 'nonce', 'uri': '/', 'algorithm': 'MD5-SESS'}
        result = _expected_rspauth(params, 'user', 'password')
        self.assertIsNone(result)

    def test_rspauth_without_qop(self) -> None:
        # Legacy digest auth (no qop): line 277 computes response directly.
        params = {'realm': 'realm', 'nonce': 'nonce', 'uri': '/'}
        result = _expected_rspauth(params, 'user', 'password')
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)


class TestHashBody(unittest.TestCase):
    def test_str_body_is_utf8_encoded(self) -> None:
        # A str body is encoded to bytes before hashing (line 303).
        result = _hash_body('hello', 'md5')
        self.assertEqual(result, _hash_body(b'hello', 'md5'))

    def test_none_body_treated_as_empty(self) -> None:
        result = _hash_body(None, 'md5')
        self.assertEqual(result, _hash_body(b'', 'md5'))

    def test_non_bytes_like_body_raises(self) -> None:
        with self.assertRaises(ValueError):
            _hash_body(iter([b'chunk']), 'md5')


class TestDigestPoolManagerEdgeCases(unittest.TestCase):
    def test_returns_401_for_non_digest_www_authenticate(self) -> None:
        # 401 response that carries only Basic auth → no Digest challenge →
        # the 401 is returned as-is (line 376).
        unauthorized = HTTPResponse(
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="realm"'},
        )

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            return_value=unauthorized,
        ) as urlopen:
            response = DigestPoolManager('user', 'password').request(
                'GET', 'http://example.com/protected'
            )

        self.assertIs(response, unauthorized)
        self.assertEqual(urlopen.call_count, 1)

    def test_preemptive_auth_int_skipped_for_streaming_body(self) -> None:
        # A cached auth-int challenge + iterator body: _with_authorization raises
        # ValueError which is silently swallowed (lines 358-359), so the request
        # is sent without an Authorization header.
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth-int"']
        )
        self.assertIsNotNone(challenge)

        ok = HTTPResponse(status=200)
        http = DigestPoolManager('user', 'password')
        http._store_challenge('http://example.com/protected', challenge)

        with mock.patch(
            'digestauth3.digest_auth.PoolManager.urlopen',
            return_value=ok,
        ) as urlopen:
            response = http.request(
                'POST',
                'http://example.com/protected',
                body=iter([b'chunk']),
            )

        self.assertIs(response, ok)
        sent_headers = urlopen.call_args_list[0].kwargs['headers']
        self.assertNotIn('Authorization', sent_headers)

    def test_store_challenge_moves_existing_key_to_end(self) -> None:
        # Storing the same challenge twice must not duplicate the entry and must
        # call move_to_end on the existing key (line 481).
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth"']
        )
        self.assertIsNotNone(challenge)

        http = DigestPoolManager('user', 'password')
        http._store_challenge('http://example.com/api', challenge)
        http._store_challenge('http://example.com/api', challenge)

        self.assertEqual(len(http._challenges), 1)

    def test_protection_space_ignores_different_origin_absolute_url(self) -> None:
        # An absolute URI in `domain` whose host differs from the request origin
        # is silently skipped (line 572); path-only URIs are still included.
        challenge = _choose_digest_challenge(
            [
                'Digest realm="realm", nonce="nonce", qop="auth", '
                'domain="http://other.com/cross /local"'
            ]
        )
        self.assertIsNotNone(challenge)

        http = DigestPoolManager('user', 'password')
        prefixes = http._protection_space_prefixes(
            'http://example.com/resource', challenge
        )
        self.assertEqual(prefixes, ['/local'])

    def test_validate_rspauth_skips_when_no_authorization_header(self) -> None:
        # If the outgoing request had no Authorization header the method returns
        # early (line 591) without raising.
        response = HTTPResponse(
            status=200,
            headers={'Authentication-Info': 'rspauth="abc"'},
        )
        http = DigestPoolManager('user', 'password')
        # Empty headers dict → no Authorization key → should not raise.
        http._validate_rspauth(response, {}, None, None)

    def test_validate_rspauth_skips_non_digest_authorization(self) -> None:
        # Authorization header with a non-Digest scheme produces an empty
        # challenges list → early return (line 595).
        response = HTTPResponse(
            status=200,
            headers={'Authentication-Info': 'rspauth="abc"'},
        )
        http = DigestPoolManager('user', 'password')
        http._validate_rspauth(
            response,
            {'Authorization': 'Basic dXNlcjpwYXNz'},
            None,
            None,
        )

    def test_validate_rspauth_raises_for_unread_auth_int_body(self) -> None:
        # auth-int qop + rspauth present + response._body is None → ProtocolError
        # (line 608); the caller must read the body before validation is possible.
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth-int"']
        )
        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge, 'GET', '/protected', 'user', 'password', 1, 'client',
        )
        response = HTTPResponse(
            status=200,
            headers={'Authentication-Info': 'rspauth="something"'},
        )
        # HTTPResponse built without body data has _body = None.
        http = DigestPoolManager('user', 'password')
        with self.assertRaises(ProtocolError):
            http._validate_rspauth(
                response,
                {'Authorization': authorization},
                None,
                challenge,
            )

    def test_auth_int_accepts_string_body(self) -> None:
        # _hash_body accepts str (line 303) so build_digest_authorization must
        # work end-to-end with a string request body.
        challenge = _choose_digest_challenge(
            ['Digest realm="realm", nonce="nonce", qop="auth-int"']
        )
        self.assertIsNotNone(challenge)
        authorization = _build_digest_authorization(
            challenge, 'POST', '/upload', 'user', 'password', 1, 'client', 'text body',
        )
        params = _parse_digest_challenges([authorization])[0]
        self.assertEqual(params['qop'], 'auth-int')


if __name__ == '__main__':
    unittest.main()
