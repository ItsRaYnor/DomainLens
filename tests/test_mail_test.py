"""The mail test: judge one received message, not only the DNS records.

The DNS checks say what a domain publishes, never whether its mail passes.
SPF can be valid and miss the service that actually sends; a DKIM key can be
published and never used; and DMARC fails most often on alignment -- SPF
passing for a service's bounce domain, not the From domain -- which no
record shows. These tests pin how one message is read: which address SPF is
judged for, what a signature check needs, when DMARC really fails, and that
anything the message cannot tell stays "not measured".

Documentation addresses (192.0.2.0/24, 198.51.100.0/24) stand in for public
ones: _public is patched to accept them, as real mail never carries them.
"""

import base64
import ipaddress
import unittest
from unittest import mock

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import mail_test
from enterprise_harness import EnterpriseAppTestCase

_DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _public(ip):
    return ip is not None and (ip.is_global or any(ip in n for n in _DOC))


def _key(bits=2048):
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    der = private.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


KEY_PEM, KEY_RECORD = _key()


class FakeLookups(mail_test.Lookups):
    """DNS from a dict: a missing name is a measured "nothing there", None
    for a value is a lookup that failed."""

    def __init__(self, txt=None, spf=("pass", "allowed"), ptr=None, addresses=None, listed=None):
        self.records = {"_dmarc.example.org": ["v=DMARC1; p=reject"],
                        "sel1._domainkey.example.org": [KEY_RECORD]}
        self.records.update(txt or {})
        self.spf_result = spf
        self.spf_calls = []
        self.ptr_names = ptr if ptr is not None else {"192.0.2.10": ["mail.example.org"]}
        self.addr = addresses if addresses is not None else {"mail.example.org": ["192.0.2.10"]}
        self.listed = listed

    def txt(self, name):
        return self.records.get(name, [])

    def spf(self, ip, mail_from, helo):
        self.spf_calls.append((ip, mail_from, helo))
        if isinstance(self.spf_result, Exception):
            raise self.spf_result
        return self.spf_result

    def ptr(self, ip):
        return self.ptr_names.get(ip, [])

    def addresses(self, host):
        return self.addr.get(host, [])

    def blocklist(self, ip):
        return self.listed


_CHAIN = (
    "Received: from inner02.prod.example.net (2001:db8::2) by inner01.prod.example.net with "
    "Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384); "
    "Mon, 5 Oct 2026 10:00:03 +0000\r\n"
    "Received: from mail.example.org (192.0.2.10) by edge01.mail.example.net (10.0.0.1) with "
    "Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384); Mon, 5 Oct 2026 10:00:02 +0000\r\n"
    "Received: from laptop (unknown [10.1.2.3]) by mail.example.org with ESMTPSA; Mon, 5 Oct 2026 10:00:01 +0000\r\n"
)


def _message(*, extra="", chain=_CHAIN, sender="Example <news@example.org>", body="Hello there.\r\n",
             return_path="<bounce@example.org>", sign=True, headers_only=False, content_type=None):
    head = (f"From: {sender}\r\nTo: someone@example.net\r\nSubject: Test\r\n"
            "Date: Mon, 5 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"
            + (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n" if content_type else "") + extra)
    message = (head + "\r\n" + body).encode()
    if sign:
        message = dkim.sign(message, b"sel1", b"example.org", KEY_PEM,
                            include_headers=[b"from", b"to", b"subject", b"date"]) + message
    top = (f"Return-Path: {return_path}\r\n" if return_path else "") + chain
    full = top.encode() + message
    if headers_only:
        full = full.split(b"\r\n\r\n", 1)[0] + b"\r\n"
    return full


def _titles(result):
    return [f["title"] for f in result["findings"]]


@mock.patch.object(mail_test, "_public", _public)
class SendingAddressTests(unittest.TestCase):
    def test_spf_is_judged_for_the_hand_over_not_an_internal_hop(self):
        """The newest hops are the receiver's own servers; judging SPF for one
        of them fails every message."""
        lookups = FakeLookups()
        result = mail_test.analyse(_message(), lookups=lookups)
        self.assertEqual([("192.0.2.10", "bounce@example.org", "mail.example.org")], lookups.spf_calls)
        self.assertEqual("TLS 1.3", result["server"]["tls_version"])
        self.assertEqual("received", result["border_source"])

    def test_the_receivers_own_received_spf_names_the_hop(self):
        chain = ("Received-SPF: Pass (example.net: domain designates 198.51.100.7 as permitted sender) "
                 "client-ip=198.51.100.7; helo=out.example.org;\r\n"
                 "Received: from relay.example.com ([198.51.100.20]) by mx.example.net with ESMTPS; Mon, 5 Oct 2026\r\n"
                 "Received: from out.example.org ([198.51.100.7]) by relay.example.com with ESMTPS; Mon, 5 Oct 2026\r\n")
        lookups = FakeLookups()
        result = mail_test.analyse(_message(chain=chain), lookups=lookups)
        self.assertEqual("198.51.100.7", lookups.spf_calls[0][0])
        self.assertEqual("received-spf", result["border_source"])

    def test_no_sending_address_is_not_measured_rather_than_failed(self):
        lookups = FakeLookups()
        result = mail_test.analyse(_message(chain=""), lookups=lookups)
        self.assertEqual("unmeasured", result["spf"]["state"])
        self.assertEqual([], lookups.spf_calls)
        self.assertFalse([t for t in _titles(result) if t.startswith("SPF")])

    def test_a_chosen_address_overrides_the_chain(self):
        lookups = FakeLookups()
        result = mail_test.analyse(_message(), lookups=lookups, ip="198.51.100.9")
        self.assertEqual("198.51.100.9", lookups.spf_calls[0][0])
        self.assertEqual("chosen", result["border_source"])
        with self.assertRaises(ValueError):
            mail_test.analyse(_message(), lookups=lookups, ip="not-an-address")

    def test_an_spf_lookup_that_failed_is_not_a_verdict(self):
        for answer in (("temperror", "timeout"), OSError("network down")):
            result = mail_test.analyse(_message(), lookups=FakeLookups(spf=answer))
            self.assertEqual("unmeasured", result["spf"]["state"], answer)

    def test_an_address_spf_does_not_allow_is_named(self):
        result = mail_test.analyse(_message(), lookups=FakeLookups(spf=("fail", "not authorized")))
        self.assertIn("SPF fails for this sender", _titles(result))


@mock.patch.object(mail_test, "_public", _public)
class DkimTests(unittest.TestCase):
    def test_a_valid_signature_passes_and_its_selector_is_learned(self):
        result = mail_test.analyse(_message(), lookups=FakeLookups())
        sig = result["dkim"]["signatures"][0]
        self.assertEqual(("measured", "pass", 2048), (sig["state"], sig["result"], sig["key_bits"]))
        self.assertEqual([{"domain": "example.org", "selector": "sel1"}], result["learned"])

    def test_a_changed_body_is_named_as_such(self):
        raw = _message().replace(b"Hello there.", b"Hello there!")
        sig = mail_test.analyse(raw, lookups=FakeLookups())["dkim"]["signatures"][0]
        self.assertEqual("fail", sig["result"])
        self.assertIn("body was changed", sig["reason"])

    def test_pasted_text_with_bare_newlines_still_verifies(self):
        """A browser textarea turns CRLF into LF; the signature is over CRLF."""
        pasted = _message().decode().replace("\r\n", "\n")
        sig = mail_test.analyse(pasted, lookups=FakeLookups())["dkim"]["signatures"][0]
        self.assertEqual("pass", sig["result"])

    def test_headers_only_cannot_verify_but_still_reads_the_key(self):
        """Outlook shows only the headers. The signature covers the body, so
        it is not measured -- not failed -- and the key is still useful."""
        result = mail_test.analyse(_message(headers_only=True), lookups=FakeLookups())
        sig = result["dkim"]["signatures"][0]
        self.assertEqual(("unmeasured", None, 2048), (sig["state"], sig["result"], sig["key_bits"]))
        self.assertEqual("unmeasured", result["dkim"]["state"])
        self.assertIsNone(result["content"])
        self.assertTrue(result["learned"])

    def test_a_missing_key_is_a_fail(self):
        lookups = FakeLookups()
        del lookups.records["sel1._domainkey.example.org"]
        sig = mail_test.analyse(_message(), lookups=lookups)["dkim"]["signatures"][0]
        self.assertEqual(("measured", "fail"), (sig["state"], sig["result"]))
        self.assertIn("No key is published", sig["reason"])

    def test_a_key_lookup_that_failed_is_not_measured(self):
        lookups = FakeLookups(txt={"sel1._domainkey.example.org": None})
        result = mail_test.analyse(_message(), lookups=lookups)
        self.assertEqual("unmeasured", result["dkim"]["signatures"][0]["state"])
        self.assertEqual([], result["learned"])

    def test_a_message_cannot_make_the_server_look_up_hundreds_of_keys(self):
        forged = "".join(f"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=s{i}; bh=x; b=x\r\n"
                         for i in range(200))
        lookups = FakeLookups()
        asked = []
        lookups.txt = lambda name: asked.append(name) or []
        mail_test.analyse(forged.encode() + _message(sign=False), lookups=lookups)
        self.assertLessEqual(len([n for n in asked if "_domainkey" in n]), 10)

    def test_unsigned_mail_is_a_finding(self):
        result = mail_test.analyse(_message(sign=False), lookups=FakeLookups())
        self.assertIn("The message is not DKIM-signed", _titles(result))

    def test_a_short_key_is_named(self):
        pem, record = _key(1024)
        raw = _message(sign=False)
        head, body = raw.split(b"\r\n\r\n", 1)
        signed = dkim.sign(raw, b"old", b"example.org", pem, include_headers=[b"from"])
        lookups = FakeLookups(txt={"old._domainkey.example.org": [record]})
        result = mail_test.analyse(signed + raw, lookups=lookups)
        self.assertIn("DKIM key of example.org is 1024 bits", _titles(result))


@mock.patch.object(mail_test, "_public", _public)
class DmarcTests(unittest.TestCase):
    def test_spf_passing_for_a_service_domain_is_not_alignment(self):
        """The most common DMARC failure, and one no DNS record shows."""
        raw = _message(sign=False, return_path="<bounce@mailer.example.com>")
        result = mail_test.analyse(raw, lookups=FakeLookups())
        self.assertEqual(("measured", "fail"), (result["dmarc"]["state"], result["dmarc"]["result"]))
        self.assertIn("mailer.example.com", result["dmarc"]["explanation"])
        self.assertIn("DMARC fails for this message", _titles(result))

    def test_an_aligned_signature_alone_passes(self):
        raw = _message(return_path="<bounce@mailer.example.com>")
        dmarc = mail_test.analyse(raw, lookups=FakeLookups())["dmarc"]
        self.assertEqual("pass", dmarc["result"])
        self.assertTrue(dmarc["dkim_aligned"])
        self.assertFalse(dmarc["spf_aligned"])

    def test_relaxed_alignment_accepts_a_subdomain_and_strict_does_not(self):
        raw = _message(sign=False, return_path="<bounce@bounces.example.org>")
        self.assertEqual("pass", mail_test.analyse(raw, lookups=FakeLookups())["dmarc"]["result"])
        strict = FakeLookups(txt={"_dmarc.example.org": ["v=DMARC1; p=reject; aspf=s"]})
        self.assertEqual("fail", mail_test.analyse(raw, lookups=strict)["dmarc"]["result"])

    def test_the_policy_of_the_organisational_domain_applies_to_a_subdomain(self):
        raw = _message(sign=False, sender="news@news.example.org", return_path="<b@news.example.org>")
        lookups = FakeLookups(txt={"_dmarc.example.org": ["v=DMARC1; p=reject; sp=quarantine"]})
        dmarc = mail_test.analyse(raw, lookups=lookups)["dmarc"]
        self.assertEqual(("example.org", "quarantine"), (dmarc["policy_domain"], dmarc["policy"]))

    def test_unmeasured_parts_do_not_make_a_fail(self):
        """SPF could not be judged and DKIM did not pass: that is not proof
        DMARC fails -- an aligned SPF pass may have been the answer."""
        raw = _message(sign=False)
        dmarc = mail_test.analyse(raw, lookups=FakeLookups(spf=("temperror", "")))["dmarc"]
        self.assertEqual("unmeasured", dmarc["state"])

    def test_a_dmarc_lookup_that_failed_is_not_measured(self):
        lookups = FakeLookups(txt={"_dmarc.example.org": None})
        self.assertEqual("unmeasured", mail_test.analyse(_message(), lookups=lookups)["dmarc"]["state"])

    def test_no_policy_and_a_monitoring_policy_are_named(self):
        lookups = FakeLookups(txt={"_dmarc.example.org": []})
        self.assertIn("No DMARC policy for the From domain", _titles(mail_test.analyse(_message(), lookups=lookups)))
        lookups = FakeLookups(txt={"_dmarc.example.org": ["v=DMARC1; p=none"]})
        self.assertIn("DMARC passes, but the policy only monitors",
                      _titles(mail_test.analyse(_message(), lookups=lookups)))


@mock.patch.object(mail_test, "_public", _public)
class ServerTests(unittest.TestCase):
    def test_no_reverse_dns_is_named_and_a_failed_lookup_is_not(self):
        result = mail_test.analyse(_message(), lookups=FakeLookups(ptr={}))
        self.assertIn("The sending address has no reverse DNS", _titles(result))
        lookups = FakeLookups()
        lookups.ptr = lambda ip: None
        result = mail_test.analyse(_message(), lookups=lookups)
        self.assertEqual("unmeasured", result["server"]["ptr_state"])
        self.assertNotIn("The sending address has no reverse DNS", _titles(result))

    def test_reverse_dns_that_does_not_point_back(self):
        result = mail_test.analyse(_message(), lookups=FakeLookups(addresses={"mail.example.org": ["192.0.2.99"]}))
        self.assertIs(False, result["server"]["fcrdns"])
        self.assertIn("Reverse DNS does not point back", _titles(result))

    def test_arrival_without_tls_is_named_and_unstated_tls_is_not(self):
        plain = "Received: from mail.example.org ([192.0.2.10]) by mx.example.net with ESMTP; Mon, 5 Oct 2026\r\n"
        result = mail_test.analyse(_message(chain=plain), lookups=FakeLookups())
        self.assertIs(False, result["server"]["tls"])
        self.assertIn("The message arrived without TLS", _titles(result))
        unstated = "Received: from mail.example.org ([192.0.2.10]) by mx.example.net; Mon, 5 Oct 2026\r\n"
        result = mail_test.analyse(_message(chain=unstated), lookups=FakeLookups())
        self.assertIsNone(result["server"]["tls"])
        self.assertNotIn("The message arrived without TLS", _titles(result))

    def test_a_listed_address_is_named(self):
        lookups = FakeLookups(listed={"listed": ["bl.example.net"], "spamhaus_dqs": False})
        self.assertIn("The sending address is on a blocklist", _titles(mail_test.analyse(_message(), lookups=lookups)))


@mock.patch.object(mail_test, "_public", _public)
class ContentTests(unittest.TestCase):
    def _html(self, html, extra=""):
        return mail_test.analyse(_message(body=html, content_type="text/html; charset=utf-8", extra=extra),
                                 lookups=FakeLookups())

    def test_a_link_that_shows_one_domain_and_leads_to_another(self):
        result = self._html('<p>Log in at <a href="https://login.example.net/x">www.example.org</a> to read on.</p>')
        self.assertIn("A link shows one address and leads to another", _titles(result))
        same = self._html('<p>Read at <a href="https://www.example.org/x">www.example.org</a> for more.</p>')
        self.assertNotIn("A link shows one address and leads to another", _titles(same))

    def test_html_without_text_and_image_only_mail(self):
        result = self._html('<img src="https://www.example.org/banner.png">')
        self.assertIn("HTML only, no plain-text part", _titles(result))
        self.assertIn("Mostly images, hardly any text", _titles(result))

    def test_bulk_mail_needs_one_click_unsubscribe(self):
        result = self._html("<p>News</p>", extra="List-Unsubscribe: <mailto:u@example.org>\r\n")
        self.assertIn("Unsubscribe is not one-click", _titles(result))
        ok = self._html("<p>News</p>", extra="List-Unsubscribe: <https://www.example.org/u>\r\n"
                                              "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")
        self.assertEqual("one-click", ok["content"]["unsubscribe"])

    def test_personal_mail_is_not_judged_as_bulk(self):
        result = mail_test.analyse(_message(), lookups=FakeLookups())
        self.assertEqual("not_applicable", result["content"]["unsubscribe"])
        self.assertFalse([t for t in _titles(result) if "nsubscribe" in t])

    def test_a_program_attached_is_named(self):
        body = ("--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n--b\r\n"
                "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\nTVo=\r\n--b--\r\n")
        result = mail_test.analyse(_message(body=body, content_type='multipart/mixed; boundary="b"'),
                                   lookups=FakeLookups())
        self.assertIn("A program or script is attached", _titles(result))

    def test_header_problems(self):
        result = mail_test.analyse(_message(sender='"ceo@example.com" <x@example.org>'), lookups=FakeLookups())
        self.assertIn("The display name shows another address", _titles(result))
        two = _message(extra="From: other@example.org\r\n")
        result = mail_test.analyse(two, lookups=FakeLookups())
        self.assertIn("The message does not have exactly one From address", _titles(result))
        self.assertEqual("unmeasured", result["dmarc"]["state"])

    def test_html_in_a_message_comes_back_as_text_only(self):
        result = self._html('<p>x</p><a href="https://www.example.org/">"><script>alert(1)</script></a>')
        self.assertTrue(all("<" not in link["text"] for link in result["content"]["links"]))


class RouteTests(EnterpriseAppTestCase):
    def test_the_page_is_listed_among_the_tools(self):
        self.login_as("user")
        page = self.client.get("/tools/mail")
        self.assertEqual(200, page.status_code)
        self.assertIn(b'href="/tools/mail"', self.client.get("/tools/dns").data)

    @mock.patch.object(mail_test, "_public", _public)
    def test_a_pasted_message_is_analysed_and_its_selector_remembered(self):
        self.login_as("user")
        with mock.patch.object(self.app_module, "_MailLookups", FakeLookups):
            resp = self.client.post("/api/mailtest", json={"message": _message().decode()})
        self.assertEqual(200, resp.status_code, resp.data)
        self.assertEqual("pass", resp.get_json()["dmarc"]["result"])
        self.assertEqual(["sel1"], mail_test.learned_selectors("example.org"))

    @mock.patch.object(mail_test, "_public", _public)
    def test_an_uploaded_file_is_analysed(self):
        import io
        self.login_as("user")
        with mock.patch.object(self.app_module, "_MailLookups", FakeLookups):
            resp = self.client.post("/api/mailtest", data={"file": (io.BytesIO(_message()), "test.eml")},
                                    content_type="multipart/form-data")
        self.assertEqual(200, resp.status_code, resp.data)

    def test_empty_oversized_and_non_messages_are_refused(self):
        self.login_as("user")
        self.assertEqual(400, self.client.post("/api/mailtest", json={"message": "  "}).status_code)
        self.assertEqual(400, self.client.post("/api/mailtest", json={"message": "just some words"}).status_code)
        big = "Subject: x\r\n\r\n" + "x" * (mail_test.MAX_BYTES + 10)
        self.assertEqual(413, self.client.post("/api/mailtest", json={"message": big}).status_code)

    def test_scans_check_the_selectors_seen_in_mail(self):
        """Selector names are otherwise guessed from a list; a key under any
        other name stayed "not found"."""
        mail_test.remember([("example.org", "s2026")])
        seen = {}
        with mock.patch.object(self.app_module, "check_dkim",
                               lambda domain, extra_selectors=None: seen.update(extra=extra_selectors)):
            self.app_module._build_check_map("example.org", "example.org")["dkim"]()
        self.assertIn("s2026", seen["extra"])


if __name__ == "__main__":
    unittest.main()
