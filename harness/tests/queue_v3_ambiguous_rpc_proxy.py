#!/usr/bin/env python3
"""One-shot loopback JSON-RPC proxy for an ambiguous loaded-v3 submission."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from enum import Enum
import fcntl
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urlsplit


WIRE_BYTES = 448
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
HTTP_TIMEOUT_SECONDS = 5.0
TOTAL_REQUEST_DEADLINE_SECONDS = 15.0
UPSTREAM_TOTAL_DEADLINE_SECONDS = 8.0
SHA256_HEX_LENGTH = 64
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}


class ProxyRequestError(ValueError):
    """The downstream body is not one supported JSON-RPC request."""


class ProxyResponseError(ValueError):
    """The upstream response cannot prove a successful transaction signature."""


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON object key')
        value[key] = item
    return value


class ForwardDecision(str, Enum):
    FORWARD_RESPONSE = 'forward_response'
    FORWARD_AND_DROP_RESPONSE = 'forward_and_drop_response'
    REJECT_DUPLICATE = 'reject_duplicate'


@dataclass(frozen=True)
class RequestClassification:
    method: str
    request_id: Any
    target_match: bool
    transaction_sha256: str | None = None
    first_signature: bytes | None = None


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    body: bytes
    content_type: str


class DeadlineGuard:
    """Close an active socket when a monotonic wall-clock deadline expires."""

    def __init__(self, timeout_seconds: float, sock: socket.socket | None = None):
        if not 0 < timeout_seconds < float('inf'):
            raise TimeoutError('request deadline has expired')
        self.deadline = time.monotonic() + timeout_seconds
        self._lock = threading.Lock()
        self._sock = sock
        self._expired = False
        self._finished = False
        self._timer = threading.Timer(timeout_seconds, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self) -> None:
        with self._lock:
            if self._finished:
                return
            self._expired = True
            sock = self._sock
            self._sock = None
        if sock is not None:
            self._shutdown_socket(sock)

    @staticmethod
    def _shutdown_socket(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self._expire()
            raise TimeoutError('total request deadline expired')
        with self._lock:
            if self._expired or self._finished:
                raise TimeoutError('total request deadline expired')
        return remaining

    def attach_socket(self, sock: socket.socket) -> None:
        with self._lock:
            expired = self._expired or self._finished or time.monotonic() >= self.deadline
            if not expired:
                self._sock = sock
        if expired:
            self._shutdown_socket(sock)
            raise TimeoutError('total request deadline expired')
        sock.settimeout(min(HTTP_TIMEOUT_SECONDS, self.remaining()))

    def close(self) -> None:
        with self._lock:
            self._finished = True
            self._sock = None
        self._timer.cancel()


def decode_shortvec(data: bytes) -> tuple[int, int]:
    """Decode Solana's canonical compact-u16 length and return (value, next offset)."""
    value = 0
    for index in range(3):
        if index >= len(data):
            raise ProxyRequestError('serialized transaction has a truncated signature count')
        byte = data[index]
        payload = byte & 0x7f
        value |= payload << (7 * index)
        if value > 0xffff:
            raise ProxyRequestError('serialized transaction signature count exceeds compact-u16')
        if byte & 0x80 == 0:
            if index > 0 and value < (1 << (7 * index)):
                raise ProxyRequestError('serialized transaction signature count is noncanonical')
            return value, index + 1
    raise ProxyRequestError('serialized transaction signature count exceeds three bytes')


def extract_first_signature(transaction: bytes) -> bytes:
    """Read the first 64-byte signature after the transaction's compact signature count."""
    count, offset = decode_shortvec(transaction)
    if count == 0:
        raise ProxyRequestError('serialized transaction has no signatures')
    signature_end = offset + count * 64
    if signature_end >= len(transaction):
        raise ProxyRequestError('serialized transaction signature list is truncated')
    return transaction[offset:offset + 64]


def encode_base58(raw: bytes) -> str:
    """Encode bytes using the canonical Bitcoin/Solana base58 alphabet."""
    if not raw:
        return ''
    zero_count = len(raw) - len(raw.lstrip(b'\0'))
    number = int.from_bytes(raw, 'big')
    encoded = ''
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return '1' * zero_count + encoded


def decode_base58_signature(signature: str) -> bytes:
    """Decode and canonical-round-trip a base58-encoded 64-byte signature."""
    if not isinstance(signature, str) or not signature or len(signature) > 100:
        raise ProxyResponseError('upstream result is not a canonical Solana signature')
    number = 0
    try:
        for character in signature:
            number = number * 58 + BASE58_INDEX[character]
    except KeyError as error:
        raise ProxyResponseError('upstream result is not a canonical Solana signature') from error
    zero_count = len(signature) - len(signature.lstrip('1'))
    body = number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else b''
    raw = bytes(zero_count) + body
    if len(raw) != 64 or encode_base58(raw) != signature:
        raise ProxyResponseError('upstream result is not a canonical 64-byte Solana signature')
    return raw


def classify_request(body: bytes, target_wire: bytes) -> RequestClassification:
    """Classify a bounded, single JSON-RPC body without changing its bytes."""
    if len(target_wire) != WIRE_BYTES:
        raise ValueError(f'target wire must be exactly {WIRE_BYTES} bytes')
    if not isinstance(body, bytes) or not body or len(body) > MAX_REQUEST_BYTES:
        raise ProxyRequestError('request body is empty or exceeds the size limit')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError) as error:
        raise ProxyRequestError('request body is not valid UTF-8 JSON') from error
    if not isinstance(value, dict) or value.get('jsonrpc') != '2.0':
        raise ProxyRequestError('request must be a single JSON-RPC 2.0 object')
    method = value.get('method')
    if not isinstance(method, str) or not method:
        raise ProxyRequestError('request method must be a nonempty string')

    if method != 'sendTransaction':
        return RequestClassification(method, value.get('id'), False)

    params = value.get('params')
    if (not isinstance(params, list) or not params or not isinstance(params[0], str)
            or len(params) < 2 or not isinstance(params[1], dict)
            or params[1].get('encoding') != 'base64'):
        return RequestClassification(method, value.get('id'), False)
    try:
        transaction = base64.b64decode(params[0], validate=True)
    except (ValueError, base64.binascii.Error):
        return RequestClassification(method, value.get('id'), False)
    if target_wire not in transaction:
        return RequestClassification(method, value.get('id'), False)
    if 'id' not in value:
        raise ProxyRequestError('matching sendTransaction must include a JSON-RPC id')
    request_id = value['id']
    if not isinstance(request_id, (str, int)) or isinstance(request_id, bool):
        raise ProxyRequestError('matching sendTransaction id must be a string or integer')
    first_signature = extract_first_signature(transaction)
    return RequestClassification(
        method, request_id, True, hashlib.sha256(transaction).hexdigest(), first_signature)


def forward_decision(classification: RequestClassification,
                     matching_submissions: int) -> ForwardDecision:
    """Pure forwarding policy used by the HTTP handler and focused unit tests."""
    if matching_submissions < 0:
        raise ValueError('matching_submissions cannot be negative')
    if not classification.target_match:
        return ForwardDecision.FORWARD_RESPONSE
    if matching_submissions == 0:
        return ForwardDecision.FORWARD_AND_DROP_RESPONSE
    return ForwardDecision.REJECT_DUPLICATE


def validate_signature_response(body: bytes, request_id: Any,
                                expected_signature: bytes) -> str:
    """Require a canonical 64-byte result equal to the serialized transaction's first signature."""
    if not body or len(body) > MAX_RESPONSE_BYTES:
        raise ProxyResponseError('upstream response is empty or exceeds the size limit')
    if len(expected_signature) != 64:
        raise ValueError('expected transaction signature must be exactly 64 bytes')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError) as error:
        raise ProxyResponseError('upstream response is not valid UTF-8 JSON') from error
    response_id = value.get('id') if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get('jsonrpc') != '2.0'
            or type(response_id) is not type(request_id) or response_id != request_id
            or 'error' in value):
        raise ProxyResponseError('upstream response is not a successful matching JSON-RPC result')
    signature = value.get('result')
    decoded_signature = decode_base58_signature(signature)
    if decoded_signature != expected_signature:
        raise ProxyResponseError('upstream signature does not match the transaction first signature')
    return signature


def is_definite_rpc_rejection(body: bytes, request_id: Any) -> bool:
    """Return true only for a complete, matching JSON-RPC error envelope."""
    if not body or len(body) > MAX_RESPONSE_BYTES:
        return False
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(value, dict):
        return False
    response_id = value.get('id')
    error = value.get('error')
    return (
        value.get('jsonrpc') == '2.0'
        and type(response_id) is type(request_id)
        and response_id == request_id
        and 'result' not in value
        and isinstance(error, dict)
        and isinstance(error.get('code'), int)
        and not isinstance(error.get('code'), bool)
        and isinstance(error.get('message'), str)
    )


def validate_upstream_url(url: str):
    """Only accept direct HTTP URLs with a numeric loopback address."""
    parsed = urlsplit(url)
    if (parsed.scheme != 'http' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError('upstream URL must be plain HTTP without credentials, query, or fragment')
    try:
        address = ipaddress.ip_address(parsed.hostname)
        port = parsed.port
    except ValueError as error:
        raise ValueError('upstream URL must use a numeric loopback address and valid port') from error
    if not address.is_loopback or port is None or not (1 <= port <= 65535):
        raise ValueError('upstream URL must use a numeric loopback address and valid port')
    if parsed.path and not parsed.path.startswith('/'):
        raise ValueError('upstream RPC path must be absolute')
    return parsed


def validate_bind_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError('bind host must be a numeric loopback address') from error
    if not address.is_loopback:
        raise ValueError('bind host must be a numeric loopback address')
    return str(address)


def _check_digest(name: str, digest: str) -> None:
    if (not isinstance(digest, str) or len(digest) != SHA256_HEX_LENGTH
            or any(char not in '0123456789abcdef' for char in digest)):
        raise ValueError(f'{name} must be a lowercase SHA-256 hex digest')


def make_receipt(target_wire_sha256: str, transaction_sha256: str,
                 signature: str | None, matching_submissions: int,
                 status: str) -> dict[str, Any]:
    """Build a receipt containing hashes and outcome fields, never transaction bytes."""
    _check_digest('target_wire_sha256', target_wire_sha256)
    _check_digest('transaction_sha256', transaction_sha256)
    if matching_submissions < 1:
        raise ValueError('matching_submissions must be positive')
    if status not in {'reserved', 'outcome_unknown', 'upstream_rejected', 'response_dropped'}:
        raise ValueError('unsupported receipt status')
    if status == 'response_dropped':
        if signature is None:
            raise ValueError('response_dropped receipt requires a signature')
        decode_base58_signature(signature)
    elif signature is not None:
        raise ValueError('only a response_dropped receipt may contain a signature')
    return {
        'schema': 'queue-v3-ambiguous-rpc-proxy-receipt-v1',
        'status': status,
        'target_wire_sha256': target_wire_sha256,
        'transaction_sha256': transaction_sha256,
        'signature': signature,
        'matching_submissions': matching_submissions,
        'duplicate_matching_submissions': matching_submissions - 1,
        'duplicate_rejected': matching_submissions > 1,
        'forward_attempted': 0 if status == 'reserved' else 1,
        'forwarded': (0 if status == 'reserved' else
                      None if status == 'outcome_unknown' else 1),
        'response_dropped': status == 'response_dropped',
    }


def atomic_write_receipt(path: str | Path, receipt: dict[str, Any]) -> None:
    """Atomically replace a receipt with a current-owner-only 0600 file."""
    destination = Path(path)
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError('receipt parent must be an existing directory')
    destination = parent / destination.name
    try:
        existing = os.lstat(destination)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not os.path.isfile(destination) or os.path.islink(destination):
            raise ValueError('receipt path must be a regular file, not a symlink')
        if existing.st_uid != os.getuid():
            raise ValueError('existing receipt must belong to the current user')

    payload = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
    fd, temporary_name = tempfile.mkstemp(prefix=f'.{destination.name}.', dir=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
        os.chmod(destination, 0o600)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


class ReceiptReservation:
    """Hold an OS-level exclusive lock for one receipt path until server shutdown.

    The 0600 sidecar inode remains reusable on disk; the kernel releases its flock
    when the owner closes or exits, so there is no PID marker to become stale.
    """

    def __init__(self, receipt_path: str | Path):
        requested_path = Path(receipt_path)
        parent = requested_path.parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError('receipt parent must be an existing directory')
        self.path = parent / requested_path.name
        self.lock_path = parent / f'{requested_path.name}.lock'
        flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.lock_path, flags, 0o600)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError('receipt reservation must be a current-owner regular file')
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError('receipt path is already reserved by another proxy') from error
            if self.path.exists() or self.path.is_symlink():
                raise ValueError('receipt path already exists; refusing to reuse an attempt')
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        fd = getattr(self, 'fd', None)
        if fd is None:
            return
        self.fd = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


class SubmissionGate:
    """Persist and enforce one matching submission across handler threads."""

    def __init__(self, target_wire: bytes, target_wire_sha256: str, receipt_path: str | Path):
        if len(target_wire) != WIRE_BYTES:
            raise ValueError(f'target wire must be exactly {WIRE_BYTES} bytes')
        _check_digest('target_wire_sha256', target_wire_sha256)
        if hashlib.sha256(target_wire).hexdigest() != target_wire_sha256:
            raise ValueError('target wire does not match its pinned SHA-256')
        self.target_wire = target_wire
        self.target_wire_sha256 = target_wire_sha256
        self.receipt_path = Path(receipt_path)
        if self.receipt_path.exists() or self.receipt_path.is_symlink():
            raise ValueError('receipt path already exists; refusing to reuse a proxy attempt')
        self.lock = threading.Lock()
        self.matching_submissions = 0
        self.transaction_sha256: str | None = None
        self.first_signature: bytes | None = None
        self.signature: str | None = None
        self.status: str | None = None

    def reserve(self, classification: RequestClassification) -> ForwardDecision:
        with self.lock:
            decision = forward_decision(classification, self.matching_submissions)
            if not classification.target_match:
                return decision
            if classification.transaction_sha256 is None:
                raise ValueError('matching transaction is missing its digest')
            if classification.first_signature is None or len(classification.first_signature) != 64:
                raise ValueError('matching transaction is missing its first signature')
            self.matching_submissions += 1
            if self.transaction_sha256 is None:
                self.transaction_sha256 = classification.transaction_sha256
                self.first_signature = classification.first_signature
                self.status = 'reserved'
            atomic_write_receipt(self.receipt_path, self._receipt())
            return decision

    def mark_outcome_unknown(self) -> None:
        with self.lock:
            if self.matching_submissions < 1 or self.transaction_sha256 is None:
                raise ValueError('cannot mark an unreserved submission as outcome-unknown')
            self.signature = None
            self.status = 'outcome_unknown'
            atomic_write_receipt(self.receipt_path, self._receipt())

    def record_success(self, signature: str) -> None:
        with self.lock:
            if self.matching_submissions < 1 or self.transaction_sha256 is None or self.first_signature is None:
                raise ValueError('cannot complete a submission without its first reservation')
            decoded_signature = decode_base58_signature(signature)
            if decoded_signature != self.first_signature:
                raise ValueError('upstream signature differs from the transaction first signature')
            self.signature = signature
            self.status = 'response_dropped'
            atomic_write_receipt(self.receipt_path, self._receipt())

    def record_upstream_rejection(self) -> None:
        with self.lock:
            if self.matching_submissions < 1 or self.transaction_sha256 is None:
                raise ValueError('cannot reject a submission without its first reservation')
            self.signature = None
            self.status = 'upstream_rejected'
            atomic_write_receipt(self.receipt_path, self._receipt())

    def record_outcome_unknown(self) -> None:
        with self.lock:
            if self.matching_submissions < 1 or self.transaction_sha256 is None:
                raise ValueError('cannot mark an unreserved submission as outcome-unknown')
            self.signature = None
            self.status = 'outcome_unknown'
            atomic_write_receipt(self.receipt_path, self._receipt())

    def _receipt(self) -> dict[str, Any]:
        assert self.transaction_sha256 is not None and self.status is not None
        return make_receipt(self.target_wire_sha256, self.transaction_sha256,
                            self.signature, self.matching_submissions, self.status)


def forward_upstream(url: str, body: bytes, content_type: str,
                     total_timeout: float = UPSTREAM_TOTAL_DEADLINE_SECONDS) -> UpstreamResponse:
    """Send the exact body once, directly to the configured loopback RPC endpoint."""
    parsed = validate_upstream_url(url)
    deadline = DeadlineGuard(total_timeout)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port,
                                            timeout=min(HTTP_TIMEOUT_SECONDS,
                                                        deadline.remaining()))
    try:
        address = ipaddress.ip_address(parsed.hostname)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        deadline.attach_socket(sock)
        destination = ((parsed.hostname, parsed.port, 0, 0) if address.version == 6
                       else (parsed.hostname, parsed.port))
        sock.connect(destination)
        connection.sock = sock
        connection.request('POST', parsed.path or '/', body=body,
                           headers={'Content-Type': content_type,
                                    'Accept': 'application/json'})
        deadline.remaining()
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        deadline.remaining()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProxyResponseError('upstream response exceeds the size limit')
        response_type = response.getheader('Content-Type', 'application/json')
        if (not isinstance(response_type, str) or '\r' in response_type
                or '\n' in response_type):
            raise ProxyResponseError('upstream returned an invalid Content-Type header')
        return UpstreamResponse(response.status, raw, response_type)
    except ProxyResponseError:
        raise
    except (TimeoutError, OSError, http.client.HTTPException) as error:
        raise ProxyResponseError('upstream request failed or timed out') from error
    finally:
        deadline.close()
        connection.close()


class _ProxyServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = False

    def __init__(self, server_address, handler_class, upstream_url, target_wire, wire_sha,
                 receipt_path, reservation: ReceiptReservation,
                 request_deadline_seconds: float = TOTAL_REQUEST_DEADLINE_SECONDS):
        if not 0 < request_deadline_seconds < float('inf'):
            raise ValueError('request deadline must be a positive finite number')
        requested_path = Path(receipt_path)
        canonical_receipt_path = requested_path.parent.resolve(strict=True) / requested_path.name
        if canonical_receipt_path != reservation.path:
            raise ValueError('server receipt path does not match its exclusive reservation')
        self.upstream_url = upstream_url
        self.reservation = reservation
        self.request_deadline_seconds = request_deadline_seconds
        self._request_deadline_local = threading.local()
        self.gate = SubmissionGate(target_wire, wire_sha, receipt_path)
        self.address_family = socket.AF_INET6 if ':' in server_address[0] else socket.AF_INET
        try:
            super().__init__(server_address, handler_class)
        except BaseException:
            reservation.close()
            raise

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(HTTP_TIMEOUT_SECONDS)
        return request, address

    def process_request_thread(self, request, client_address):
        deadline = DeadlineGuard(self.request_deadline_seconds, request)
        self._request_deadline_local.guard = deadline
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_deadline_local.guard = None
            deadline.close()

    def remaining_request_seconds(self) -> float:
        deadline = getattr(self._request_deadline_local, 'guard', None)
        if deadline is None:
            return self.request_deadline_seconds
        return deadline.remaining()

    def server_close(self):
        try:
            super().server_close()
        finally:
            self.reservation.close()


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        # Request and response data are intentionally not logged.
        return

    def _reply(self, status: int, body: bytes, content_type: str = 'application/json') -> None:
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (OSError, TimeoutError):
            pass

    def _error(self, status: int, message: str) -> None:
        body = json.dumps({'error': message}, separators=(',', ':')).encode('utf-8')
        self._reply(status, body)

    def do_POST(self):
        if self.path != '/' or self.headers.get('Transfer-Encoding') is not None:
            self._error(400, 'only one fixed-length POST to / is supported')
            return
        lengths = self.headers.get_all('Content-Length') or []
        if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > len(str(MAX_REQUEST_BYTES))):
            self._error(411, 'a single Content-Length is required')
            return
        length = int(lengths[0])
        if length < 1 or length > MAX_REQUEST_BYTES:
            self._error(413, 'request body is empty or exceeds the size limit')
            return
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                raise ProxyRequestError('request body ended before Content-Length')
            classification = classify_request(body, self.server.gate.target_wire)
        except ProxyRequestError:
            self._error(400, 'invalid single JSON-RPC request')
            return

        try:
            decision = self.server.gate.reserve(classification)
        except (OSError, ValueError):
            self._error(500, 'private attempt receipt could not be written')
            return
        if decision is ForwardDecision.REJECT_DUPLICATE:
            self._error(409, 'matching transaction submission already reserved')
            return

        if decision is ForwardDecision.FORWARD_AND_DROP_RESPONSE:
            try:
                self.server.gate.mark_outcome_unknown()
            except (OSError, ValueError):
                self._error(500, 'private attempt receipt could not be updated')
                return

        content_type = self.headers.get('Content-Type', 'application/json')
        try:
            upstream = forward_upstream(
                self.server.upstream_url, body, content_type,
                total_timeout=min(UPSTREAM_TOTAL_DEADLINE_SECONDS,
                                  self.server.remaining_request_seconds()))
        except (ProxyResponseError, TimeoutError):
            if classification.target_match:
                try:
                    self.server.gate.record_outcome_unknown()
                except (OSError, ValueError):
                    pass
                self._error(502, 'matching submission outcome is unknown')
            else:
                self._error(502, 'upstream request failed or exceeded a response limit')
            return

        if decision is ForwardDecision.FORWARD_AND_DROP_RESPONSE:
            if is_definite_rpc_rejection(upstream.body, classification.request_id):
                try:
                    self.server.gate.record_upstream_rejection()
                except (OSError, ValueError):
                    self._error(500, 'private attempt receipt could not be updated')
                    return
                self._error(502, 'upstream definitively rejected the matching submission')
                return
            try:
                if not 200 <= upstream.status < 300:
                    raise ProxyResponseError('upstream returned a non-success HTTP status')
                if classification.first_signature is None:
                    raise ProxyResponseError('matching transaction has no parsed first signature')
                signature = validate_signature_response(
                    upstream.body, classification.request_id, classification.first_signature)
                self.server.gate.record_success(signature)
            except (ProxyResponseError, OSError, ValueError):
                try:
                    self.server.gate.record_outcome_unknown()
                except (OSError, ValueError):
                    pass
                self._error(502, 'matching submission outcome is unknown')
                return
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return

        self._reply(upstream.status, upstream.body, upstream.content_type)

    def do_GET(self):
        self._error(405, 'only POST is supported')

    def do_PUT(self):
        self._error(405, 'only POST is supported')

    def do_DELETE(self):
        self._error(405, 'only POST is supported')


def load_pinned_wire(path: str | Path, expected_sha256: str) -> bytes:
    """Read one canonical, private, fixed-size pinned wire without following symlinks."""
    _check_digest('wire_sha256', expected_sha256)
    requested_path = Path(path)
    if not requested_path.is_absolute():
        raise ValueError('pinned Full wire path must be absolute and canonical')
    try:
        canonical_path = requested_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError('pinned Full wire path must exist and be canonical') from error
    if canonical_path != requested_path:
        raise ValueError('pinned Full wire path must be canonical and contain no symlinks')

    try:
        metadata = os.lstat(requested_path)
    except OSError as error:
        raise ValueError('pinned Full wire must be an existing regular file') from error

    def validate_metadata(file_metadata) -> None:
        if (not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_uid != os.getuid()):
            raise ValueError('pinned Full wire must be a current-owner regular file')
        mode = stat.S_IMODE(file_metadata.st_mode)
        if mode & 0o077 or not mode & stat.S_IRUSR or mode & 0o111:
            raise ValueError('pinned Full wire must be owner-readable with owner-only permissions')
        if file_metadata.st_size != WIRE_BYTES:
            raise ValueError(f'pinned Full wire must be exactly {WIRE_BYTES} bytes')

    validate_metadata(metadata)
    flags = (os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
             | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        fd = os.open(requested_path, flags)
    except OSError as error:
        raise ValueError('pinned Full wire could not be opened without following symlinks') from error
    try:
        opened_metadata = os.fstat(fd)
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError('pinned Full wire changed while it was being opened')
        validate_metadata(opened_metadata)
        wire = os.read(fd, WIRE_BYTES + 1)
        if len(wire) != WIRE_BYTES or os.fstat(fd).st_size != WIRE_BYTES:
            raise ValueError(f'pinned Full wire must be exactly {WIRE_BYTES} bytes')
    finally:
        os.close(fd)
    if hashlib.sha256(wire).hexdigest() != expected_sha256:
        raise ValueError('pinned Full wire SHA-256 mismatch')
    return wire


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream-url', required=True,
                        help='loopback validator JSON-RPC URL, for example http://127.0.0.1:8899')
    parser.add_argument('--bind-host', default='127.0.0.1', help='numeric loopback address (default: 127.0.0.1)')
    parser.add_argument('--port', required=True, type=int, help='local proxy port')
    parser.add_argument('--wire-path', '--full-wire-path', dest='wire_path', required=True,
                        help='pinned 448-byte Full wire file')
    parser.add_argument('--wire-sha256', '--full-wire-sha256', dest='wire_sha256', required=True,
                        help='pinned Full wire SHA-256')
    parser.add_argument('--receipt-path', required=True, help='new owner-only attempt receipt path')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validate_upstream_url(args.upstream_url)
    bind_host = validate_bind_host(args.bind_host)
    if not 1 <= args.port <= 65535:
        raise SystemExit('--port must be between 1 and 65535')
    wire = load_pinned_wire(args.wire_path, args.wire_sha256)
    receipt_path = Path(args.receipt_path)
    if not receipt_path.parent.exists() or not receipt_path.parent.is_dir():
        raise SystemExit('receipt parent directory must already exist')
    reservation = ReceiptReservation(receipt_path)
    try:
        server = _ProxyServer((bind_host, args.port), _ProxyHandler, args.upstream_url,
                              wire, args.wire_sha256, receipt_path, reservation)
    except BaseException:
        reservation.close()
        raise
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
