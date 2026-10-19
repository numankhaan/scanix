import copy
import json
from pathlib import Path
import unittest

from scanix.service.parsers import clean, greeting_protocol, identify, protocol_response
from scanix.service.registry import load_registry, safe_regex, validate
from scanix.core.udp_protocols import udp_payload


class RegistryTests(unittest.TestCase):
    def test_original_signature_fixtures(self):
        fixtures=json.loads(Path(__file__).with_name('fixtures').joinpath('signatures-v1.json').read_text())
        tested=set()
        for fixture in fixtures:
            with self.subTest(signature=fixture['signature']):
                positive=identify(fixture['protocol'],fixture['positive'].encode(),'fixture')
                self.assertEqual(positive.signature_id,fixture['signature'])
                negative=identify(fixture['protocol'],fixture['negative'].encode(),'fixture')
                self.assertTrue(negative is None or negative.signature_id != fixture['signature'])
                self.assertFalse(positive.authenticated)
                tested.add(fixture['signature'])
        self.assertEqual(tested, set(load_registry().signatures)-{'tls.response.v1','dns.response.v1','ntp.response.v1'})

    def test_wire_signatures(self):
        self.assertIsNone(identify('tls',b'fake','tls.tcp.v1'))
        self.assertEqual(identify('tls',b'','tls.tcp.v1',tls_handshake=True).signature_id,'tls.response.v1')
        for protocol, port in (('dns',53),('ntp',123)):
            _,request=udp_payload(port)
            if protocol=='dns':
                reply=request[:2]+b'\x80'+request[3:]
            else:
                reply=bytearray(48);reply[0]=0x24;reply[24:32]=request[40:48];reply=bytes(reply)
            with self.subTest(protocol=protocol):
                self.assertEqual(identify(protocol,reply,'fixture',request=request).signature_id,protocol+'.response.v1')
                self.assertIsNone(identify(protocol,reply,'fixture',request=b'bad'))

    def test_regex_safety(self):
        for pattern in ('^(a+)+$', '^a.*$', '^(?=x)x$', r'^(a)\1$', '^a{0,999999}$', '^a|b$', 'unanchored'):
            with self.subTest(pattern=pattern),self.assertRaises(ValueError):
                safe_regex(pattern)

    def test_database_rejects_code_and_bad_references(self):
        source=Path(__file__).parents[1]/'data'/'probes-v1.json'
        base=json.loads(source.read_text())
        for key,value in (('parser_id','os.system'),('response_limit',999999),('fallbacks',['missing']),('payload_strategy','eval')):
            data=copy.deepcopy(base);data['probes'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate(data)

    def test_limits_malformed_and_selected_headers(self):
        for wire in (b'HTTP/1.1 200 OK\r\nX: no end', b'HTTP/1.1 200 OK\r\n Bad: fold\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\nServer: a\r\nServer: b\r\n\r\n', b'HTTP/1.1 200 OK\r\nX: \x1b\r\n\r\n',
                     b'x'*16385):
            self.assertIsNone(protocol_response('http',wire))
        parsed=protocol_response('http',b'HTTP/1.1 200 OK\r\nSet-Cookie: secret\r\nAuthorization: secret\r\nServer: Lab/1\r\n\r\n')
        self.assertEqual(parsed['headers'],{'server':'Lab/1'})
        self.assertEqual(clean('hello\x1b[31m\x00\nworld'), 'hello?[31m??world')

    def test_ambiguous_greeting_and_capability_confirmation(self):
        self.assertIsNone(greeting_protocol(b'220 ready\r\n'))
        self.assertEqual(identify('pop3',b'+OK ready\r\n','fixture').confidence,'banner')
        for protocol,command,data in (
            ('smtp','ehlo',b'250-lab.invalid\r\n250 STARTTLS\r\n'),
            ('ftp','feat',b'211-Features\r\n UTF8\r\n211 End\r\n'),
            ('pop3','capa',b'+OK capabilities\r\nSTLS\r\n.\r\n'),
            ('imap','capability',b'* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n')):
            self.assertEqual(identify(protocol,data,'fixture',command=command).confidence,'protocol')
            self.assertIsNone(identify(protocol,data[:-2],'fixture',command=command))

    def test_invalid_database_shapes_and_duplicate_ids(self):
        source=Path(__file__).parents[1]/'data'/'probes-v1.json'
        base=json.loads(source.read_text())
        for malformed in (None, [], {}, {**base,'schema_version':True}, {**base,'database_version':None}, {**base,'probes':[None]},
                          {**base,'probes':base['probes']+[base['probes'][0]]}):
            with self.subTest(value=str(malformed)[:50]),self.assertRaises(ValueError):validate(malformed)
