import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'queue_v3_ambiguous_rpc_proxy', Path(__file__).with_name('queue_v3_ambiguous_rpc_proxy.py'))
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


def _child_reserve_code():
    return (
        "import importlib.util,sys\n"
        f"spec=importlib.util.spec_from_file_location('proxy', {str(Path(__file__).with_name('queue_v3_ambiguous_rpc_proxy.py'))!r})\n"
        "module=importlib.util.module_from_spec(spec)\n"
        "sys.modules[spec.name]=module\n"
        "spec.loader.exec_module(module)\n"
        "try:\n"
        " reservation=module.ReceiptReservation(sys.argv[1])\n"
        " reservation.close()\n"
        "except ValueError:\n"
        " raise SystemExit(3)\n"
    )


class AmbiguousRpcProxyTests(unittest.TestCase):
    def setUp(self):
        self.wire = bytes(range(256)) + bytes(range(192))
        self.first_signature = bytes(range(64))
        self.tx = b'\x01' + self.first_signature + b'message-prefix' + self.wire + b'suffix'

    def request(self, method='sendTransaction', transaction=None, request_id=7):
        if transaction is None:
            transaction = base64.b64encode(self.tx).decode('ascii')
        return json.dumps({
            'jsonrpc': '2.0', 'id': request_id, 'method': method,
            'params': [transaction, {'encoding': 'base64'}],
        }, separators=(',', ':')).encode()

    def test_classifies_exact_wire_inside_base64_transaction(self):
        body = self.request()
        classification = m.classify_request(body, self.wire)
        self.assertEqual(classification.method, 'sendTransaction')
        self.assertTrue(classification.target_match)
        self.assertEqual(classification.transaction_sha256, hashlib.sha256(self.tx).hexdigest())
        self.assertEqual(classification.first_signature, self.first_signature)
        self.assertEqual(m.forward_decision(classification, matching_submissions=0),
                         m.ForwardDecision.FORWARD_AND_DROP_RESPONSE)

    def test_ordinary_request_forwards_without_claiming_a_matching_submission(self):
        body = self.request(method='getSlot')
        classification = m.classify_request(body, self.wire)
        self.assertFalse(classification.target_match)
        self.assertEqual(m.forward_decision(classification, matching_submissions=0),
                         m.ForwardDecision.FORWARD_RESPONSE)

    def test_ordinary_non_base64_send_transaction_is_forwardable(self):
        body = self.request(transaction='base58-encoded-transaction')
        classification = m.classify_request(body, self.wire)
        self.assertFalse(classification.target_match)
        self.assertEqual(m.forward_decision(classification, matching_submissions=0),
                         m.ForwardDecision.FORWARD_RESPONSE)

    def test_second_matching_submission_is_rejected(self):
        classification = m.classify_request(self.request(), self.wire)
        self.assertEqual(m.forward_decision(classification, matching_submissions=1),
                         m.ForwardDecision.REJECT_DUPLICATE)

    def test_rejects_batches_and_forwards_non_base64_transaction_encodings(self):
        batch = b'[{"jsonrpc":"2.0","id":1,"method":"getSlot"}]'
        with self.assertRaises(m.ProxyRequestError):
            m.classify_request(batch, self.wire)
        duplicate_key = b'{"jsonrpc":"2.0","id":1,"method":"getSlot","method":"sendTransaction"}'
        with self.assertRaises(m.ProxyRequestError):
            m.classify_request(duplicate_key, self.wire)
        body = self.request()
        value = json.loads(body)
        value['params'][1]['encoding'] = 'base58'
        classification = m.classify_request(json.dumps(value).encode(), self.wire)
        self.assertFalse(classification.target_match)
        self.assertEqual(m.forward_decision(classification, matching_submissions=0),
                         m.ForwardDecision.FORWARD_RESPONSE)

    def test_signature_response_requires_canonical_transaction_signature(self):
        signature = m.encode_base58(self.first_signature)
        valid = json.dumps({'jsonrpc': '2.0', 'id': 7, 'result': signature}).encode()
        self.assertEqual(m.validate_signature_response(valid, 7, self.first_signature), signature)
        other_signature = m.encode_base58(bytes([9]) * 64)
        for response in (
                b'{"jsonrpc":"2.0","id":7,"result":""}',
                b'{"jsonrpc":"2.0","id":8,"result":"5ig"}',
                b'{"jsonrpc":"2.0","id":7,"error":{"code":-1}}',
                b'{"jsonrpc":"2.0","id":7,"id":7,"result":"5ig"}',
                json.dumps({'jsonrpc': '2.0', 'id': 7, 'result': other_signature}).encode(),
                b'{"jsonrpc":"2.0","id":7,"result":"0"}'):
            with self.subTest(response=response), self.assertRaises(m.ProxyResponseError):
                m.validate_signature_response(response, 7, self.first_signature)

    def test_shortvec_signature_count_is_canonical_and_bounds_signature_list(self):
        tx = b'\x02' + self.first_signature + bytes([7]) * 64 + b'message'
        self.assertEqual(m.extract_first_signature(tx), self.first_signature)
        self.assertEqual(m.decode_shortvec(b'\x80\x01'), (128, 2))
        for malformed in (b'\x81\x00' + self.first_signature + b'message',
                          b'\x80\x00',
                          b'\x02' + self.first_signature + b'message',
                          b'\x80\x80\x80' + self.first_signature):
            with self.subTest(malformed=malformed), self.assertRaises(m.ProxyRequestError):
                m.extract_first_signature(malformed)

    def test_rpc_error_envelope_is_distinguished_from_ambiguous_outcome(self):
        rejection = b'{"jsonrpc":"2.0","id":7,"error":{"code":-32002,"message":"rejected"}}'
        self.assertTrue(m.is_definite_rpc_rejection(rejection, 7))
        self.assertFalse(m.is_definite_rpc_rejection(
            b'{"jsonrpc":"2.0","id":8,"error":{"code":-32002,"message":"rejected"}}', 7))
        self.assertFalse(m.is_definite_rpc_rejection(
            b'{"jsonrpc":"2.0","id":7,"result":"signature"}', 7))

    def test_receipt_is_scrubbed_and_written_owner_only(self):
        tx_sha = hashlib.sha256(self.tx).hexdigest()
        wire_sha = hashlib.sha256(self.wire).hexdigest()
        signature = m.encode_base58(self.first_signature)
        receipt = m.make_receipt(wire_sha, tx_sha, signature=signature, matching_submissions=1,
                                 status='response_dropped')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            m.atomic_write_receipt(path, receipt)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            receipt_text = path.read_text()
            stored = json.loads(receipt_text)
        self.assertEqual(stored['target_wire_sha256'], wire_sha)
        self.assertEqual(stored['transaction_sha256'], tx_sha)
        self.assertEqual(stored['signature'], signature)
        self.assertEqual(stored['forwarded'], 1)
        self.assertTrue(stored['response_dropped'])
        self.assertNotIn(self.tx.hex(), receipt_text)
        self.assertNotIn(base64.b64encode(self.wire).decode(), receipt_text)

    def test_gate_records_rejected_duplicate_without_losing_first_signature(self):
        classification = m.classify_request(self.request(), self.wire)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            gate = m.SubmissionGate(self.wire, hashlib.sha256(self.wire).hexdigest(), path)
            self.assertEqual(gate.reserve(classification), m.ForwardDecision.FORWARD_AND_DROP_RESPONSE)
            self.assertEqual(gate.reserve(classification), m.ForwardDecision.REJECT_DUPLICATE)
            gate.mark_outcome_unknown()
            gate.record_success(m.encode_base58(self.first_signature))
            self.assertEqual(gate.reserve(classification), m.ForwardDecision.REJECT_DUPLICATE)
            receipt = json.loads(path.read_text())
        self.assertEqual(receipt['matching_submissions'], 3)
        self.assertEqual(receipt['duplicate_matching_submissions'], 2)
        self.assertTrue(receipt['duplicate_rejected'])
        self.assertEqual(receipt['signature'], m.encode_base58(self.first_signature))
        self.assertEqual(receipt['forwarded'], 1)
        self.assertTrue(receipt['response_dropped'])

    def test_receipt_records_unknown_and_definite_rejection_separately(self):
        classification = m.classify_request(self.request(), self.wire)
        with tempfile.TemporaryDirectory() as directory:
            unknown_path = Path(directory) / 'unknown.json'
            unknown = m.SubmissionGate(self.wire, hashlib.sha256(self.wire).hexdigest(), unknown_path)
            unknown.reserve(classification)
            unknown.mark_outcome_unknown()
            unknown_receipt = json.loads(unknown_path.read_text())
            rejected_path = Path(directory) / 'rejected.json'
            rejected = m.SubmissionGate(self.wire, hashlib.sha256(self.wire).hexdigest(), rejected_path)
            rejected.reserve(classification)
            rejected.mark_outcome_unknown()
            rejected.record_upstream_rejection()
            rejected_receipt = json.loads(rejected_path.read_text())
        self.assertEqual(unknown_receipt['status'], 'outcome_unknown')
        self.assertEqual(unknown_receipt['forward_attempted'], 1)
        self.assertIsNone(unknown_receipt['forwarded'])
        self.assertFalse(unknown_receipt['response_dropped'])
        self.assertEqual(rejected_receipt['status'], 'upstream_rejected')
        self.assertEqual(rejected_receipt['forwarded'], 1)
        self.assertFalse(rejected_receipt['response_dropped'])

    def test_receipt_reservation_is_exclusive_across_processes_and_released(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            reservation = m.ReceiptReservation(path)
            try:
                blocked = subprocess.run([sys.executable, '-c', _child_reserve_code(), str(path)],
                                         capture_output=True, text=True, check=False)
                self.assertEqual(blocked.returncode, 3, blocked.stderr)
            finally:
                reservation.close()
            acquired = subprocess.run([sys.executable, '-c', _child_reserve_code(), str(path)],
                                      capture_output=True, text=True, check=False)
            self.assertEqual(acquired.returncode, 0, acquired.stderr)

    def test_server_holds_receipt_reservation_until_close(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            reservation = m.ReceiptReservation(path)
            server = m._ProxyServer(('127.0.0.1', 0), m._ProxyHandler,
                                    'http://127.0.0.1:8899', self.wire,
                                    hashlib.sha256(self.wire).hexdigest(), path, reservation)
            try:
                blocked = subprocess.run([sys.executable, '-c', _child_reserve_code(), str(path)],
                                         capture_output=True, text=True, check=False)
                self.assertEqual(blocked.returncode, 3, blocked.stderr)
            finally:
                server.server_close()
            acquired = subprocess.run([sys.executable, '-c', _child_reserve_code(), str(path)],
                                      capture_output=True, text=True, check=False)
            self.assertEqual(acquired.returncode, 0, acquired.stderr)

    def test_existing_ambiguous_receipt_prevents_path_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            m.atomic_write_receipt(path, {'status': 'outcome_unknown'})
            with self.assertRaises(ValueError):
                m.ReceiptReservation(path)

    def test_upstream_and_bind_must_be_numeric_loopback(self):
        self.assertEqual(m.validate_upstream_url('http://127.0.0.1:8899').hostname, '127.0.0.1')
        self.assertEqual(m.validate_bind_host('127.0.0.1'), '127.0.0.1')
        for url in ('https://127.0.0.1:8899', 'http://example.com:8899',
                    'http://127.0.0.1:8899@evil.example'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                m.validate_upstream_url(url)
        with self.assertRaises(ValueError):
            m.validate_bind_host('0.0.0.0')

    def test_load_pinned_wire_accepts_owner_only_exact_file_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'wire.bin'
            path.write_bytes(self.wire)
            os.chmod(path, 0o600)
            self.assertEqual(m.load_pinned_wire(
                path, hashlib.sha256(self.wire).hexdigest()), self.wire)
            with self.assertRaises(ValueError):
                m.load_pinned_wire(path, '0' * 64)

    def test_load_pinned_wire_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory).resolve()
            target = directory_path / 'wire.bin'
            target.write_bytes(self.wire)
            os.chmod(target, 0o600)
            link = directory_path / 'wire-link.bin'
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                m.load_pinned_wire(link, hashlib.sha256(self.wire).hexdigest())

    def test_load_pinned_wire_rejects_wrong_size_and_permissions(self):
        expected_sha = hashlib.sha256(self.wire).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'wire.bin'
            path.write_bytes(self.wire + b'x')
            os.chmod(path, 0o600)
            with self.assertRaises(ValueError):
                m.load_pinned_wire(path, expected_sha)

            path.write_bytes(self.wire)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                m.load_pinned_wire(path, expected_sha)

            os.chmod(path, 0o600)
            original_uid = os.getuid()
            with patch.object(m.os, 'getuid', return_value=original_uid + 1):
                with self.assertRaises(ValueError):
                    m.load_pinned_wire(path, expected_sha)

    def test_load_pinned_wire_rejects_relative_paths(self):
        with self.assertRaises(ValueError):
            m.load_pinned_wire('relative-wire.bin', hashlib.sha256(self.wire).hexdigest())

    def test_upstream_deadline_bounds_slow_drip_response(self):
        class SlowDripHandler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_POST(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', '20')
                self.end_headers()
                for _ in range(20):
                    try:
                        self.wfile.write(b'x')
                        self.wfile.flush()
                    except OSError:
                        break
                    time.sleep(0.03)

            def log_message(self, format, *args):
                return

        class LocalServer(ThreadingHTTPServer):
            def server_bind(self):
                socketserver.TCPServer.server_bind(self)
                self.server_name = self.server_address[0]
                self.server_port = self.server_address[1]

            def handle_error(self, request, client_address):
                return

        upstream = LocalServer(('127.0.0.1', 0), SlowDripHandler)
        upstream.daemon_threads = True
        serving = threading.Thread(target=upstream.serve_forever, daemon=True)
        serving.start()
        started = time.monotonic()
        try:
            with self.assertRaises(m.ProxyResponseError):
                m.forward_upstream(f'http://127.0.0.1:{upstream.server_port}', b'{}',
                                   'application/json', total_timeout=0.15)
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            upstream.shutdown()
            upstream.server_close()
            serving.join(timeout=1)

    def test_upstream_deadline_is_attached_before_connect(self):
        class BlockingConnectSocket:
            def __init__(self):
                self.closed = threading.Event()
                self.connect_started = threading.Event()
                self.timeout = None
                self.timeout_at_connect = None

            def settimeout(self, timeout):
                self.timeout = timeout

            def connect(self, destination):
                self.timeout_at_connect = self.timeout
                self.connect_started.set()
                if not self.closed.wait(timeout=0.5):
                    return
                raise OSError('deadline closed socket during connect')

            def shutdown(self, how):
                self.closed.set()

            def close(self):
                self.closed.set()

        fake_socket = BlockingConnectSocket()
        started = time.monotonic()
        with patch.object(m.socket, 'socket', return_value=fake_socket):
            with self.assertRaises(m.ProxyResponseError):
                m.forward_upstream('http://127.0.0.1:8899', b'{}',
                                   'application/json', total_timeout=0.1)
        self.assertTrue(fake_socket.connect_started.is_set())
        self.assertIsNotNone(fake_socket.timeout_at_connect)
        self.assertTrue(fake_socket.closed.is_set())
        self.assertLess(time.monotonic() - started, 0.4)

    def test_server_total_deadline_closes_a_stalled_request_body(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / 'receipt.json'
            reservation = m.ReceiptReservation(receipt_path)
            server = m._ProxyServer(('127.0.0.1', 0), m._ProxyHandler,
                                    'http://127.0.0.1:8899', self.wire,
                                    hashlib.sha256(self.wire).hexdigest(), receipt_path,
                                    reservation, request_deadline_seconds=0.2)
            serving = threading.Thread(target=server.serve_forever, daemon=True)
            serving.start()
            client = socket.create_connection(server.server_address, timeout=1)
            client.settimeout(1)
            client.sendall(
                b'POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n'
                b'Content-Type: application/json\r\n\r\n{')
            started = time.monotonic()
            try:
                self.assertEqual(client.recv(1), b'')
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                client.close()
                server.shutdown()
                server.server_close()
                serving.join(timeout=1)
            self.assertFalse(serving.is_alive())


if __name__ == '__main__':
    unittest.main()
