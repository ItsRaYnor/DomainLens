"""Outlook .msg files, and PDFs -- attached or on their own -- in the mail analysis.

An .msg file was refused ("it should start with header lines"), though it is
what Outlook saves. Its received headers are kept apart from the body, the
body is sometimes only compressed RTF with the HTML wrapped inside, and the
body is not kept as it was sent -- so a DKIM signature over it cannot be
verified, which must read "not measured", never "fails".

A PDF attachment was judged by its name alone. A phishing PDF carries a
link ("click to view the document"), a form that sends what is typed, or
JavaScript that runs on opening; those are now found, also when compressed
or written with #xx escapes, and its links are checked like the message's
own. A PDF can be scanned on its own too.
"""

import io
import unittest
import zlib
from unittest import mock

import cfb_writer
import mail_test
import msg_file
import pdf_scan
from enterprise_harness import EnterpriseAppTestCase
from test_mail_test import FakeLookups, _message, _public, _titles

# [MS-OXRTFCP] 3.1.1.1: "{\rtf1\ansi\ansicpg1252\pard hello world}\r\n", compressed.
_RTF_EXAMPLE = bytes.fromhex("2d0000002b0000004c5a4675f1c5c7a703000a00726370673132354232"
                             "0af32068656c0900206277" "05b06c647d0a800fa0")


def _pdf(*objects, compress=None):
    """A small PDF; `compress` puts that object's text in a Flate stream."""
    body = b"%PDF-1.7\n"
    for n, obj in enumerate(objects, 1):
        body += f"{n} 0 obj\n".encode() + obj + b"\nendobj\n"
    if compress is not None:
        packed = zlib.compress(compress)
        body += (f"{len(objects) + 1} 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /Length {len(packed)} >>\n"
                 .encode() + b"stream\n" + packed + b"\nendstream\nendobj\n")
    return body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


_PAGE = b"<< /Type /Page /Annots [<< /Subtype /Link /A << /S /URI /URI (https://login.example.net/view) >> >>] >>"


class PdfScanTests(unittest.TestCase):
    def test_a_link_in_a_one_page_pdf_is_found(self):
        result = pdf_scan.scan(_pdf(b"<< /Type /Catalog >>", _PAGE))
        self.assertEqual("scanned", result["state"])
        self.assertEqual(["https://login.example.net/view"], result["uris"])
        titles = [t for _s, t, _d in pdf_scan.findings(result, "invoice.pdf")]
        self.assertIn("A one-page PDF with a link", titles)

    def test_javascript_hidden_in_a_compressed_stream_that_runs_on_opening_is_high(self):
        hidden = b"<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>"
        result = pdf_scan.scan(_pdf(b"<< /Type /Catalog >>", compress=hidden))
        found = {t: s for s, t, _d in pdf_scan.findings(result, "a.pdf")}
        self.assertEqual("high", found["A PDF contains JavaScript"])

    def test_a_name_written_with_escapes_is_still_found(self):
        result = pdf_scan.scan(_pdf(b"<< /Type /Catalog /Names << /J#61vaScript 3 0 R >> >>"))
        self.assertEqual(1, result["counts"]["javascript"])

    def test_launch_embedded_files_and_forms_are_named(self):
        result = pdf_scan.scan(_pdf(b"<< /A << /S /Launch /F (cmd.exe) >> >>",
                                    b"<< /EmbeddedFiles 4 0 R >>",
                                    b"<< /A << /S /SubmitForm /F (https://collect.example.net/) >> >>"))
        found = {t: s for s, t, _d in pdf_scan.findings(result, "a.pdf")}
        self.assertEqual("high", found["A PDF can start a program"])
        self.assertEqual("medium", found["A PDF carries another file"])
        self.assertEqual("medium", found["A PDF form sends what is typed"])

    def test_a_hex_written_link_is_read(self):
        hexed = "https://example.net/a".encode().hex().encode()
        result = pdf_scan.scan(_pdf(b"<< /A << /S /URI /URI <" + hexed + b"> >> >>"))
        self.assertEqual(["https://example.net/a"], result["uris"])

    def test_an_encrypted_pdf_is_not_measured_not_linkless(self):
        result = pdf_scan.scan(_pdf(b"<< /Type /Catalog >>", b"<< /Filter /Standard /V 4 >>") .replace(
            b"trailer\n<< /Root 1 0 R >>", b"trailer\n<< /Root 1 0 R /Encrypt 2 0 R >>"))
        self.assertEqual("partial", result["state"])
        self.assertIn("encrypted", result["reason"])
        self.assertIn("An encrypted PDF could not be read", [t for _s, t, _d in pdf_scan.findings(result, "a.pdf")])

    def test_a_web_page_named_pdf_is_said_to_be_one(self):
        result = pdf_scan.scan(b"<!DOCTYPE html><html><form action='https://example.net'>")
        self.assertEqual(("not_pdf", "a web page"), (result["state"], result["kind"]))
        found = {t: s for s, t, _d in pdf_scan.findings(result, "invoice.pdf")}
        self.assertEqual("medium", found["A file named .pdf is not a PDF"])

    def test_a_stream_that_unpacks_to_too_much_is_cut_off(self):
        bomb = zlib.compress(b"\x00" * (pdf_scan._MAX_STREAM_OUT + 1024 * 1024), 9)
        data = (b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + bomb + b"\nendstream\nendobj\n")
        result = pdf_scan.scan(data)
        self.assertEqual("partial", result["state"])
        self.assertTrue(result["cut"])


class MsgTests(unittest.TestCase):
    HEADERS = ("Received: from mail.example.org (192.0.2.10) by mx.example.net with ESMTPS; Mon, 5 Oct 2026 10:00:02 +0000\r\n"
               "Authentication-Results: mx.example.net; dkim=pass header.d=example.org header.s=sel1\r\n"
               "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=sel1; h=from; bh=x; b=abc\r\n"
               "From: Example <news@example.org>\r\nTo: someone@example.net\r\nSubject: Test\r\n"
               "Date: Mon, 5 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"
               "Content-Type: multipart/alternative; boundary=gone\r\n")

    def test_the_rtf_example_of_the_specification_unpacks(self):
        self.assertEqual(b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n", msg_file.decompress_rtf(_RTF_EXAMPLE))

    def test_html_wrapped_in_rtf_comes_out_with_its_links(self):
        rtf = (b"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1 \\deff0{\\fonttbl{\\f0\\fswiss Arial;}}"
               b"{\\*\\htmltag19 <html>}{\\*\\htmltag84 <a href=\"https://example.net/login\">}"
               b"\\htmlrtf {\\field{\\*\\fldinst{HYPERLINK \"https://example.net/login\"}}{\\fldrslt\\htmlrtf0 Log in\\htmlrtf }}\\htmlrtf0"
               b"{\\*\\htmltag92 </a>}{\\*\\htmltag27 </html>}}")
        html = msg_file.html_from_rtf(rtf)
        self.assertIn('<a href="https://example.net/login">Log in</a>', html)
        self.assertNotIn("Arial", html)

    def test_an_outlook_message_keeps_its_received_headers_and_attachments(self):
        data = cfb_writer.msg(headers=self.HEADERS, body="Hello", html="<p>Hello</p>",
                              attachments=[("invoice.pdf", "application/pdf", _pdf(b"<< /Type /Catalog >>", _PAGE))])
        raw, info = msg_file.to_message(data)
        self.assertEqual((True, "html", 1), (info["headers"], info["body"], info["attachments"]))
        self.assertNotIn(b"boundary=gone", raw)
        self.assertIn(b"Received: from mail.example.org (192.0.2.10)", raw)

    @mock.patch.object(mail_test, "_public", _public)
    def test_dkim_over_a_rebuilt_body_is_not_measured_and_the_receiver_is_shown(self):
        raw, _ = msg_file.to_message(cfb_writer.msg(headers=self.HEADERS, body="Hello"))
        result = mail_test.analyse(raw, lookups=FakeLookups(), origin="msg")
        sig = result["dkim"]["signatures"][0]
        self.assertEqual(("unmeasured", None, "pass"), (sig["state"], sig["result"], sig.get("receiver")))
        # Not checked at all, rather than checked, failed and excused.
        self.assertEqual(mail_test._NOT_AS_SENT, sig["reason"])
        self.assertEqual("msg", result["origin"])
        self.assertNotIn("DKIM signature of example.org fails", _titles(result))
        self.assertEqual("192.0.2.10", result["spf"]["ip"])

    def test_a_file_that_is_not_an_outlook_message_is_refused_in_words(self):
        with self.assertRaises(msg_file.MsgError):
            msg_file.to_message(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)


class _Links(FakeLookups):
    def check_links(self, urls):
        return {"feeds": {u: "listed" for u in urls}, "virustotal": {"state": "off", "results": {}}}


@mock.patch.object(mail_test, "_public", _public)
class AttachmentTests(unittest.TestCase):
    def test_a_pdf_attachments_link_is_checked_like_the_messages_own(self):
        import email.message
        part = email.message.EmailMessage()
        part.set_content("See the attachment.")
        part.add_attachment(_pdf(b"<< /Type /Catalog >>", _PAGE), maintype="application", subtype="pdf",
                            filename="invoice.pdf")
        body = part.as_bytes().split(b"\n\n", 1)
        message = _message(sign=False, content_type=part["Content-Type"], body=body[1].decode())
        result = mail_test.analyse(message, lookups=_Links())
        link = next(l for l in result["content"]["links"] if l.get("source") == "invoice.pdf")
        self.assertEqual(("login.example.net", "listed"), (link["host"], link["feed"]))
        self.assertIn("A link is on a threat list", _titles(result))
        self.assertEqual("scanned", result["content"]["attachments"][0]["scan"]["state"])


class ApiTests(EnterpriseAppTestCase):
    def _post(self, data, name):
        self.login_as("user")
        with mock.patch.object(mail_test, "_public", _public):
            return self.client.post("/api/mailtest", data={"file": (io.BytesIO(data), name)},
                                    content_type="multipart/form-data")

    def test_a_pdf_on_its_own_is_scanned(self):
        body = self._post(_pdf(b"<< /Type /Catalog >>", _PAGE), "document.pdf").get_json()
        self.assertEqual("file", body["kind"])
        self.assertEqual(["https://login.example.net/view"], body["file"]["scan"]["urls"])
        self.assertEqual("pdf", body["file"]["scan"]["type"])

    def test_an_outlook_message_is_analysed(self):
        data = cfb_writer.msg(headers=MsgTests.HEADERS, body="Hello")
        body = self._post(data, "message.msg").get_json()
        self.assertEqual(("message", "msg", True), (body["kind"], body["origin"], body["msg"]["headers"]))

    def test_the_page_takes_any_file(self):
        """Any file can be analysed, so the picker does not narrow the choice."""
        self.login_as("user")
        html = self.client.get("/tools/mail").get_data(as_text=True)
        self.assertIn('<input type="file" id="mailTestFile">', html)


if __name__ == "__main__":
    unittest.main()
