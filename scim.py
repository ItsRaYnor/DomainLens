"""SCIM 2.0 user provisioning for DomainLens (Entra ID / Azure AD).

Preferred authentication for the SCIM endpoint is OAuth 2.0 client credentials
against POST /oauth/token (scope=scim). A static bearer token remains supported
as a legacy fallback.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional
from urllib.parse import unquote

from flask import Flask, jsonify, request

import db

log = logging.getLogger("domainlens.scim")

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCIM_DOMAINLENS_SCHEMA = "urn:ietf:params:scim:schemas:extension:domainlens:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_CONTENT_TYPE = "application/scim+json"

# Entra "default logical" / common org attributes → DomainLens columns
# Keys are lowercase path/attribute names accepted from SCIM payloads.
_LOGICAL_ATTR_MAP = {
    "department": "department",
    "companyname": "company_name",
    "company": "company_name",
    "organization": "organization",
    "division": "division",
    "costcenter": "cost_center",
    "employeenumber": "employee_number",
    "employeeid": "employee_number",
    "jobtitle": "job_title",
    "title": "job_title",
    "office": "office_location",
    "officelocation": "office_location",
    "physicaldeliveryofficename": "office_location",
    "telephonenumber": "phone_number",
    "phone": "phone_number",
    "phonenumber": "phone_number",
    "mobile": "mobile_number",
    "mobilenumber": "mobile_number",
    "preferredlanguage": "preferred_language",
    "streetaddress": "street_address",
    "city": "city",
    "locality": "city",
    "state": "state",
    "region": "state",
    "postalcode": "postal_code",
    "country": "country",
}

_FILTER_USER_NAME = re.compile(
    r'userName\s+eq\s+"([^"]+)"',
    re.IGNORECASE,
)
_FILTER_EXTERNAL_ID = re.compile(
    r'externalId\s+eq\s+"([^"]+)"',
    re.IGNORECASE,
)


def _settings() -> dict:
    try:
        from settings.store import get_store
        return dict(get_store().section("scim", force_reload=True))
    except Exception:
        return {}


def scim_config() -> dict:
    raw = _settings()
    enabled = bool(raw.get("enabled", False)) or (
        (os.environ.get("SCIM_ENABLED") or "").strip().lower() in {"1", "true", "yes", "on"}
    )
    auth_mode = (
        (raw.get("auth_mode") or "")
        or os.environ.get("SCIM_AUTH_MODE")
        or "oauth"
    ).strip().lower()
    if auth_mode not in {"oauth", "bearer", "both"}:
        auth_mode = "oauth"
    default_role = (raw.get("default_role") or os.environ.get("SCIM_DEFAULT_ROLE") or "user").strip().lower()
    if default_role not in {"user", "admin"}:
        default_role = "user"
    return {
        "enabled": enabled,
        "auth_mode": auth_mode,  # oauth preferred; bearer = legacy static token; both = accept either
        "default_role": default_role,
        "prefer_oauth": auth_mode in {"oauth", "both"},
        "allow_legacy_bearer": auth_mode in {"bearer", "both"},
        "base_path": "/scim/v2",
    }


def scim_status() -> dict:
    cfg = scim_config()
    import scim_oauth

    return {
        "enabled": cfg["enabled"],
        "auth_mode": cfg["auth_mode"],
        "prefer_oauth": cfg["prefer_oauth"],
        "allow_legacy_bearer": cfg["allow_legacy_bearer"],
        "oauth_token_endpoint": "/oauth/token",
        "oauth_configured": scim_oauth.oauth_client_configured(),
        "legacy_bearer_configured": scim_oauth.legacy_bearer_configured(),
        "configured": cfg["enabled"]
        and (
            (cfg["prefer_oauth"] and scim_oauth.oauth_client_configured())
            or (cfg["allow_legacy_bearer"] and scim_oauth.legacy_bearer_configured())
        ),
        "users_endpoint": "/scim/v2/Users",
        "supported_attributes": [
            "externalId",
            "userName",
            "emails",
            "displayName",
            "active",
            "title",
            "department",
            "companyName",
            "manager",
            "employeeNumber",
            "organization",
            "division",
            "costCenter",
            "officeLocation",
            "phoneNumbers",
            "addresses",
            "preferredLanguage",
        ],
    }


def _error(status: int, detail: str, scim_type: str | None = None):
    body = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    resp = jsonify(body)
    resp.status_code = status
    resp.headers["Content-Type"] = SCIM_CONTENT_TYPE
    return resp


def _scim_json(payload: dict, status: int = 200):
    resp = jsonify(payload)
    resp.status_code = status
    resp.headers["Content-Type"] = SCIM_CONTENT_TYPE
    return resp


def _display_name(payload: dict) -> str:
    name = payload.get("name") or {}
    if isinstance(name, dict):
        formatted = (name.get("formatted") or "").strip()
        if formatted:
            return formatted
        given = (name.get("givenName") or "").strip()
        family = (name.get("familyName") or "").strip()
        joined = f"{given} {family}".strip()
        if joined:
            return joined
    display = (payload.get("displayName") or "").strip()
    if display:
        return display
    return (payload.get("userName") or "user").split("@")[0]


def _primary_email(payload: dict, user_name: str) -> str:
    emails = payload.get("emails") or []
    if isinstance(emails, list):
        primary = next((e for e in emails if isinstance(e, dict) and e.get("primary") and e.get("value")), None)
        if primary:
            return str(primary["value"]).strip().lower()
        first = next((e for e in emails if isinstance(e, dict) and e.get("value")), None)
        if first:
            return str(first["value"]).strip().lower()
    return (user_name or "").strip().lower()


def _role_from_payload(payload: dict, default_role: str) -> str:
    roles = payload.get("roles") or []
    if isinstance(roles, list):
        for item in roles:
            value = ""
            if isinstance(item, dict):
                value = str(item.get("value") or item.get("display") or "").lower()
            else:
                value = str(item).lower()
            if "admin" in value:
                return "admin"
    return default_role if default_role in {"user", "admin"} else "user"


def _enterprise_block(payload: dict) -> dict:
    block = payload.get(SCIM_ENTERPRISE_SCHEMA)
    return block if isinstance(block, dict) else {}


def _domainlens_block(payload: dict) -> dict:
    block = payload.get(SCIM_DOMAINLENS_SCHEMA)
    return block if isinstance(block, dict) else {}


def _manager_fields(raw) -> dict:
    """Normalize manager from string, objectId, or {value, displayName, $ref}."""
    out = {"manager_external_id": None, "manager_display_name": None}
    if raw is None or raw == "":
        return out
    if isinstance(raw, str):
        out["manager_external_id"] = raw.strip() or None
        return out
    if isinstance(raw, dict):
        value = (
            raw.get("value")
            or raw.get("managerId")
            or raw.get("objectId")
            or raw.get("id")
            or ""
        )
        display = raw.get("displayName") or raw.get("display") or ""
        out["manager_external_id"] = str(value).strip() or None
        out["manager_display_name"] = str(display).strip() or None
    return out


def _set_logical(updates: dict, key: str, value) -> None:
    mapped = _LOGICAL_ATTR_MAP.get(key.replace(" ", "").replace("_", "").lower())
    if not mapped:
        return
    if value is None or (isinstance(value, str) and not value.strip()):
        updates[mapped] = None
    else:
        updates[mapped] = str(value).strip()


def profile_from_scim_payload(payload: dict) -> dict:
    """
    Extract department, companyName, manager, and other default logical attrs.

    Accepts:
    - core fields (title, phoneNumbers, addresses, preferredLanguage)
    - enterprise extension (department, organization, division, costCenter,
      employeeNumber, manager)
    - top-level aliases Entra sometimes sends (companyName, department, …)
    - domainlens extension for extras → scim_profile JSON
    """
    updates: dict[str, Any] = {}
    enterprise = _enterprise_block(payload)
    domainlens = _domainlens_block(payload)

    # Enterprise extension (preferred for department / manager / org)
    for src, dest in (
        ("department", "department"),
        ("organization", "organization"),
        ("division", "division"),
        ("costCenter", "cost_center"),
        ("employeeNumber", "employee_number"),
    ):
        if src in enterprise:
            val = enterprise.get(src)
            updates[dest] = str(val).strip() if val is not None and str(val).strip() else None
    if "manager" in enterprise:
        updates.update(_manager_fields(enterprise.get("manager")))

    # Top-level / Entra logical aliases (companyName, department, manager, …)
    for key in (
        "department",
        "companyName",
        "company",
        "organization",
        "division",
        "costCenter",
        "employeeNumber",
        "employeeId",
        "jobTitle",
        "title",
        "officeLocation",
        "physicalDeliveryOfficeName",
        "preferredLanguage",
    ):
        if key in payload:
            _set_logical(updates, key, payload.get(key))
    if "manager" in payload and "manager_external_id" not in updates:
        updates.update(_manager_fields(payload.get("manager")))

    # Core: title
    if payload.get("title") and "job_title" not in updates:
        _set_logical(updates, "title", payload.get("title"))

    # Core: phoneNumbers
    phones = payload.get("phoneNumbers") or []
    if isinstance(phones, list):
        for phone in phones:
            if not isinstance(phone, dict) or not phone.get("value"):
                continue
            ptype = (phone.get("type") or "work").lower()
            if ptype in {"mobile", "cell"}:
                updates["mobile_number"] = str(phone["value"]).strip()
            elif "phone_number" not in updates or ptype in {"work", "phone"}:
                updates["phone_number"] = str(phone["value"]).strip()

    # Core: addresses
    addresses = payload.get("addresses") or []
    if isinstance(addresses, list) and addresses:
        primary = next((a for a in addresses if isinstance(a, dict) and a.get("primary")), None)
        addr = primary or next((a for a in addresses if isinstance(a, dict)), None) or {}
        for src, dest in (
            ("streetAddress", "street_address"),
            ("locality", "city"),
            ("region", "state"),
            ("postalCode", "postal_code"),
            ("country", "country"),
        ):
            if addr.get(src):
                updates[dest] = str(addr[src]).strip()

    if payload.get("preferredLanguage"):
        updates["preferred_language"] = str(payload["preferredLanguage"]).strip()

    # companyName: prefer explicit; also mirror into organization if empty
    if updates.get("company_name") and not updates.get("organization"):
        updates["organization"] = updates["company_name"]
    if updates.get("organization") and not updates.get("company_name"):
        updates["company_name"] = updates["organization"]

    # DomainLens extension + unknown logical attrs → scim_profile bag
    extra = {}
    if isinstance(domainlens, dict):
        for key, val in domainlens.items():
            normalized = key.replace(" ", "").replace("_", "")
            if normalized.lower() in _LOGICAL_ATTR_MAP or key in {
                "department", "companyName", "manager", "officeLocation", "jobTitle"
            }:
                if key.lower() == "manager" or normalized.lower() == "manager":
                    updates.update(_manager_fields(val))
                else:
                    _set_logical(updates, key, val)
            else:
                extra[key] = val
    # Preserve prior extras merge happens at call site when patching
    if "CompanyName" in payload:
        _set_logical(updates, "companyName", payload.get("CompanyName"))
    if extra:
        updates["scim_profile"] = extra

    return updates


def user_to_scim(user: dict) -> dict:
    email = user.get("email") or ""
    enterprise: dict[str, Any] = {}
    for src, scim_key in (
        ("employee_number", "employeeNumber"),
        ("cost_center", "costCenter"),
        ("organization", "organization"),
        ("division", "division"),
        ("department", "department"),
    ):
        if user.get(src):
            enterprise[scim_key] = user[src]
    if user.get("manager_external_id") or user.get("manager_display_name"):
        mgr: dict[str, Any] = {}
        if user.get("manager_external_id"):
            mgr["value"] = user["manager_external_id"]
        if user.get("manager_display_name"):
            mgr["displayName"] = user["manager_display_name"]
        enterprise["manager"] = mgr

    phone_numbers = []
    if user.get("phone_number"):
        phone_numbers.append({"type": "work", "value": user["phone_number"], "primary": True})
    if user.get("mobile_number"):
        phone_numbers.append({"type": "mobile", "value": user["mobile_number"]})

    addresses = []
    if any(user.get(k) for k in ("street_address", "city", "state", "postal_code", "country")):
        addresses.append(
            {
                "type": "work",
                "primary": True,
                "streetAddress": user.get("street_address"),
                "locality": user.get("city"),
                "region": user.get("state"),
                "postalCode": user.get("postal_code"),
                "country": user.get("country"),
            }
        )

    domainlens_ext: dict[str, Any] = {}
    if user.get("company_name"):
        domainlens_ext["companyName"] = user["company_name"]
    if user.get("office_location"):
        domainlens_ext["officeLocation"] = user["office_location"]
    profile_extra = user.get("scim_profile") or {}
    if isinstance(profile_extra, dict):
        domainlens_ext.update(profile_extra)

    schemas = [SCIM_USER_SCHEMA]
    out: dict[str, Any] = {
        "schemas": schemas,
        "id": str(user["id"]),
        "externalId": user.get("external_id") or None,
        "userName": user.get("user_name") or email,
        "displayName": user.get("name") or email,
        "name": {
            "formatted": user.get("name") or email,
        },
        "emails": [
            {
                "value": email,
                "type": "work",
                "primary": True,
            }
        ],
        "active": bool(user.get("enabled", True)),
        "meta": {
            "resourceType": "User",
            "created": user.get("created_at"),
            "lastModified": user.get("updated_at"),
            "location": f"/scim/v2/Users/{user['id']}",
        },
        "roles": [{"value": user.get("role") or "user", "primary": True}],
    }
    if user.get("job_title"):
        out["title"] = user["job_title"]
    if user.get("preferred_language"):
        out["preferredLanguage"] = user["preferred_language"]
    if phone_numbers:
        out["phoneNumbers"] = phone_numbers
    if addresses:
        out["addresses"] = addresses
    # Top-level aliases (handy for Entra custom mappings / logical attrs)
    if user.get("department"):
        out["department"] = user["department"]
    if user.get("company_name"):
        out["companyName"] = user["company_name"]
    if enterprise:
        schemas.append(SCIM_ENTERPRISE_SCHEMA)
        out[SCIM_ENTERPRISE_SCHEMA] = enterprise
    if domainlens_ext:
        schemas.append(SCIM_DOMAINLENS_SCHEMA)
        out[SCIM_DOMAINLENS_SCHEMA] = domainlens_ext
    out["schemas"] = schemas
    return out


def _apply_patch(user: dict, operations: list) -> dict:
    updates: dict[str, Any] = {}
    for op in operations or []:
        if not isinstance(op, dict):
            continue
        kind = (op.get("op") or "").strip().lower()
        path = (op.get("path") or "").strip()
        value = op.get("value")
        path_l = path.lower()
        # Strip schema prefix from patch paths
        for prefix in (
            SCIM_ENTERPRISE_SCHEMA.lower() + ":",
            SCIM_DOMAINLENS_SCHEMA.lower() + ":",
        ):
            if path_l.startswith(prefix):
                path_l = path_l[len(prefix) :]
                path = path.split(":", 1)[-1] if ":" in path else path

        if kind in {"replace", "add"}:
            if not path or path_l == "active":
                if isinstance(value, dict) and "active" in value:
                    updates["enabled"] = bool(value.get("active"))
                elif path_l == "active":
                    updates["enabled"] = bool(value)
            if path_l == "username" or (isinstance(value, dict) and "userName" in value):
                uname = value if not isinstance(value, dict) else value.get("userName")
                if uname:
                    updates["user_name"] = str(uname).strip()
                    if "@" in str(uname):
                        updates["email"] = str(uname).strip().lower()
            if path_l == "externalid" or (isinstance(value, dict) and "externalId" in value):
                ext = value if not isinstance(value, dict) else value.get("externalId")
                updates["external_id"] = (str(ext).strip() if ext is not None else None)
            if path_l == "displayname" or path_l == "name.formatted":
                updates["name"] = str(value).strip() if value is not None else user.get("name")
            if path_l.startswith("emails") and isinstance(value, list) and value:
                email = value[0].get("value") if isinstance(value[0], dict) else value[0]
                if email:
                    updates["email"] = str(email).strip().lower()
            if path_l in {"department", "companyname", "company", "organization", "division",
                          "costcenter", "employeenumber", "employeeid", "jobtitle", "title",
                          "officelocation", "physicaldeliveryofficename", "preferredlanguage"}:
                _set_logical(updates, path_l, value)
            if path_l == "manager" or path_l.endswith(".manager"):
                updates.update(_manager_fields(value))
            if path_l.startswith("manager."):
                leaf = path_l.split(".", 1)[1]
                if leaf in {"value", "managerid", "objectid", "id"}:
                    updates["manager_external_id"] = str(value).strip() if value else None
                elif leaf in {"displayname", "display"}:
                    updates["manager_display_name"] = str(value).strip() if value else None
            if isinstance(value, dict):
                if "displayName" in value:
                    updates["name"] = str(value["displayName"]).strip()
                if "emails" in value and isinstance(value["emails"], list) and value["emails"]:
                    ev = value["emails"][0]
                    email = ev.get("value") if isinstance(ev, dict) else ev
                    if email:
                        updates["email"] = str(email).strip().lower()
                # Whole enterprise object replace
                nested = profile_from_scim_payload(value if "userName" in value or "emails" in value else {
                    SCIM_ENTERPRISE_SCHEMA: value.get(SCIM_ENTERPRISE_SCHEMA, value),
                    **{k: value[k] for k in ("department", "companyName", "manager", "title") if k in value},
                })
                for k, v in nested.items():
                    if k == "scim_profile":
                        merged = dict(user.get("scim_profile") or {})
                        merged.update(v or {})
                        updates["scim_profile"] = merged
                    else:
                        updates[k] = v
        elif kind == "remove":
            if path_l == "active":
                updates["enabled"] = False
            elif path_l in _LOGICAL_ATTR_MAP or path_l.replace(".", "") in {
                "manager", "manager.value", "manager.displayname"
            }:
                if path_l.startswith("manager"):
                    updates["manager_external_id"] = None
                    updates["manager_display_name"] = None
                else:
                    _set_logical(updates, path_l, None)
    return updates


def require_scim_auth(view):
    from functools import wraps
    import scim_oauth

    @wraps(view)
    def wrapped(*args, **kwargs):
        cfg = scim_config()
        if not cfg["enabled"]:
            return _error(503, "SCIM provisioning is disabled")
        ok, err = scim_oauth.authenticate_scim_request(request, cfg)
        if not ok:
            return _error(401, err or "Unauthorized", scim_type="invalidValue")
        return view(*args, **kwargs)

    return wrapped


def register_routes(app: Flask) -> None:
    @app.get("/scim/v2/ServiceProviderConfig")
    @require_scim_auth
    def scim_service_provider_config():
        return _scim_json(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "patch": {"supported": True},
                "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
                "filter": {"supported": True, "maxResults": 200},
                "changePassword": {"supported": False},
                "sort": {"supported": False},
                "etag": {"supported": False},
                "authenticationSchemes": [
                    {
                        "type": "oauthbearertoken",
                        "name": "OAuth Bearer Token",
                        "description": "Preferred: OAuth 2.0 client credentials via /oauth/token (scope=scim)",
                        "specUri": "http://www.rfc-editor.org/info/rfc6750",
                        "primary": True,
                    },
                    {
                        "type": "oauthbearertoken",
                        "name": "Long-lived Bearer Token",
                        "description": "Legacy static SCIM_BEARER_TOKEN",
                        "primary": False,
                    },
                ],
            }
        )

    @app.get("/scim/v2/ResourceTypes")
    @require_scim_auth
    def scim_resource_types():
        return _scim_json(
            {
                "schemas": [SCIM_LIST_SCHEMA],
                "totalResults": 1,
                "startIndex": 1,
                "itemsPerPage": 1,
                "Resources": [
                    {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                        "id": "User",
                        "name": "User",
                        "endpoint": "/Users",
                        "schema": SCIM_USER_SCHEMA,
                        "schemaExtensions": [
                            {
                                "schema": SCIM_ENTERPRISE_SCHEMA,
                                "required": False,
                            },
                            {
                                "schema": SCIM_DOMAINLENS_SCHEMA,
                                "required": False,
                            },
                        ],
                    }
                ],
            }
        )

    @app.get("/scim/v2/Schemas")
    @require_scim_auth
    def scim_schemas():
        return _scim_json(
            {
                "schemas": [SCIM_LIST_SCHEMA],
                "totalResults": 3,
                "Resources": [
                    {"id": SCIM_USER_SCHEMA, "name": "User", "description": "User Account"},
                    {
                        "id": SCIM_ENTERPRISE_SCHEMA,
                        "name": "EnterpriseUser",
                        "description": "Enterprise User (department, manager, organization, …)",
                    },
                    {
                        "id": SCIM_DOMAINLENS_SCHEMA,
                        "name": "DomainLensUser",
                        "description": "DomainLens logical attrs (companyName, officeLocation, extras)",
                    },
                ],
            }
        )

    @app.get("/scim/v2/Users")
    @require_scim_auth
    def scim_list_users():
        filter_q = request.args.get("filter") or ""
        start_index = request.args.get("startIndex", 1)
        count = request.args.get("count", 100)
        user_name = None
        external_id = None
        if filter_q:
            m = _FILTER_USER_NAME.search(filter_q)
            if m:
                user_name = unquote(m.group(1))
            m = _FILTER_EXTERNAL_ID.search(filter_q)
            if m:
                external_id = unquote(m.group(1))
        result = db.find_users_for_scim(
            user_name=user_name,
            external_id=external_id,
            start_index=start_index,
            count=count,
        )
        resources = [user_to_scim(u) for u in result["items"]]
        return _scim_json(
            {
                "schemas": [SCIM_LIST_SCHEMA],
                "totalResults": result["total"],
                "startIndex": result["start_index"],
                "itemsPerPage": len(resources),
                "Resources": resources,
            }
        )

    @app.post("/scim/v2/Users")
    @require_scim_auth
    def scim_create_user():
        payload = request.get_json(silent=True) or {}
        cfg = scim_config()
        user_name = (payload.get("userName") or "").strip()
        if not user_name:
            return _error(400, "userName is required", scim_type="invalidValue")
        email = _primary_email(payload, user_name)
        if not email or "@" not in email:
            return _error(400, "A valid email (userName or emails) is required", scim_type="invalidValue")
        existing = db.get_user_by_email(email) or db.get_user_by_user_name(user_name)
        ext = (payload.get("externalId") or "").strip() or None
        if ext and db.get_user_by_external_id(ext):
            return _error(409, "User already exists", scim_type="uniqueness")
        if existing:
            return _error(409, "User already exists", scim_type="uniqueness")
        active = payload.get("active", True)
        profile = profile_from_scim_payload(payload)
        user_id = db.create_user(
            email=email,
            password_hash=None,
            name=_display_name(payload),
            role=_role_from_payload(payload, cfg["default_role"]),
            enabled=bool(active),
            provider="scim",
            external_id=ext,
            user_name=user_name,
            **profile,
        )
        user = db.get_user(user_id)
        log.info("SCIM provisioned user %s (id=%s)", email, user_id)
        return _scim_json(user_to_scim(user), status=201)

    @app.get("/scim/v2/Users/<user_id>")
    @require_scim_auth
    def scim_get_user(user_id: str):
        try:
            uid = int(user_id)
        except ValueError:
            return _error(404, "User not found")
        user = db.get_user(uid)
        if not user:
            return _error(404, "User not found")
        return _scim_json(user_to_scim(user))

    @app.put("/scim/v2/Users/<user_id>")
    @require_scim_auth
    def scim_replace_user(user_id: str):
        try:
            uid = int(user_id)
        except ValueError:
            return _error(404, "User not found")
        user = db.get_user(uid)
        if not user:
            return _error(404, "User not found")
        payload = request.get_json(silent=True) or {}
        cfg = scim_config()
        user_name = (payload.get("userName") or user.get("user_name") or user.get("email") or "").strip()
        email = _primary_email(payload, user_name) or user.get("email")
        updates = {
            "email": email,
            "user_name": user_name,
            "name": _display_name(payload),
            "enabled": bool(payload.get("active", True)),
            "role": _role_from_payload(payload, user.get("role") or cfg["default_role"]),
            "provider": user.get("provider") or "scim",
        }
        if "externalId" in payload:
            updates["external_id"] = (str(payload.get("externalId") or "").strip() or None)
        profile = profile_from_scim_payload(payload)
        if "scim_profile" in profile:
            merged = dict(user.get("scim_profile") or {})
            merged.update(profile.pop("scim_profile") or {})
            profile["scim_profile"] = merged
        updates.update(profile)
        updated = db.update_user(uid, **updates)
        return _scim_json(user_to_scim(updated))

    @app.patch("/scim/v2/Users/<user_id>")
    @require_scim_auth
    def scim_patch_user(user_id: str):
        try:
            uid = int(user_id)
        except ValueError:
            return _error(404, "User not found")
        user = db.get_user(uid)
        if not user:
            return _error(404, "User not found")
        payload = request.get_json(silent=True) or {}
        ops = payload.get("Operations") or payload.get("operations") or []
        updates = _apply_patch(user, ops)
        # Also accept a full enterprise block in PATCH value without path
        if isinstance(payload.get("value"), dict):
            updates.update(profile_from_scim_payload(payload["value"]))
        if "scim_profile" in updates:
            merged = dict(user.get("scim_profile") or {})
            merged.update(updates["scim_profile"] or {})
            updates["scim_profile"] = merged
        if updates:
            user = db.update_user(uid, **updates)
        return _scim_json(user_to_scim(user))

    @app.delete("/scim/v2/Users/<user_id>")
    @require_scim_auth
    def scim_delete_user(user_id: str):
        try:
            uid = int(user_id)
        except ValueError:
            return _error(404, "User not found")
        user = db.get_user(uid)
        if not user:
            return _error(404, "User not found")
        # Soft-delete preferred for audit; hard-delete if already disabled + query
        if request.args.get("hard") == "1":
            db.delete_user(uid)
        else:
            db.update_user(uid, enabled=False)
        return ("", 204)
