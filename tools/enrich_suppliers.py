# Copyright 2024-Present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SBOM Supplier Enrichment Tool.

This module enriches a CycloneDX SBOM (JSON) with supplier information for
components that lack it. Supplier data is derived dynamically from public
package registries (currently PyPI) to avoid hard-coding.

High level workflow:
 1. Load existing SBOM JSON.
 2. Iterate components (and the top-level metadata.component if present).
 3. For Python (pypi) components missing a supplier, query the PyPI JSON API.
 4. Extract maintainer/author names, emails, and key project URLs.
 5. Persist the updated SBOM (in place unless an explicit output file path
    is supplied).

Exit codes:
 0 success
 1 usage / argument error
 2 I/O or JSON parse error
 3 unexpected runtime error

Usage (CLI):
  python tools/enrich_suppliers.py --input sbom.json            # in place
  python tools/enrich_suppliers.py -i sbom.json -o enriched.json
  python tools/enrich_suppliers.py -i sbom.json -v              # verbose logs

The SBOM is expected to follow CycloneDX JSON structure (1.4+). Components
should be in the top-level "components" array. This script is tolerant of
missing fields.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

_LOGGER = logging.getLogger("sbom.supplier_enricher")

# Default small pause between registry requests to avoid hammering PyPI.
_DEFAULT_REQUEST_DELAY_SEC = 0.1
# Network timeout for a single registry call.
_DEFAULT_TIMEOUT_SEC = 10


class PyPIClient:
    """Minimal PyPI JSON API client with in-memory caching.

    Methods are intentionally small; extend for other registries in future.
    """

    def __init__(self, request_delay: float = _DEFAULT_REQUEST_DELAY_SEC, timeout: int = _DEFAULT_TIMEOUT_SEC) -> None:
        self._cache: dict[str, dict[str, Any] | None] = {}
        self._request_delay = request_delay
        self._timeout = timeout

    def get_package(self, name: str) -> dict[str, Any] | None:
        """Return PyPI JSON metadata for a package name or None if unavailable.

        The name should be normalized (no version specifiers). Any transient
        failure returns None (we log a warning). Persistent errors won't abort
        the entire enrichment process.
        """
        if name in self._cache:
            return self._cache[name]

        # Basic sanitation: reject names that look unsafe for URL composition.
        if not re.match(r"^[A-Za-z0-9._-]+$", name):  # conservative
            _LOGGER.debug("Skipping PyPI lookup due to suspicious name: %s", name)
            self._cache[name] = None
            return None

        url = f"https://pypi.org/pypi/{name}/json"
        # Explicit scheme assertion for security linters.
        if not url.startswith("https://"):
            _LOGGER.debug("Unexpected scheme in URL, aborting: %s", url)
            self._cache[name] = None
            return None
        time.sleep(self._request_delay)
        try:
            # URL scheme validated above; approved for open.
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310 (validated scheme)
                if resp.status != 200:
                    _LOGGER.debug("PyPI non-200 (%s) for %s", resp.status, name)
                    self._cache[name] = None
                    return None
                data = json.loads(resp.read().decode("utf-8"))
                self._cache[name] = data
                return data
        except (HTTPError, URLError, json.JSONDecodeError) as exc:
            _LOGGER.debug("PyPI lookup failed for %s: %s", name, exc)
            self._cache[name] = None
            return None


def _extract_pypi_supplier(meta: dict[str, Any]) -> dict[str, Any] | None:
    """Extract supplier structure from a PyPI metadata document.

    The PyPI JSON metadata has an "info" object containing author / maintainer
    data. We prefer maintainer over author when present. We gather:
      - name (maintainer or author)
      - contact list with email (if valid)
      - up to three project URLs (homepage, repository, source)
    Returns None if nothing usable is found.
    """
    info = meta.get("info", {}) if isinstance(meta, dict) else {}
    if not info:
        return None

    maintainer = (info.get("maintainer") or "").strip()
    maintainer_email = (info.get("maintainer_email") or "").strip()
    author = (info.get("author") or "").strip()
    author_email = (info.get("author_email") or "").strip()

    name = maintainer or author
    email = maintainer_email or author_email

    supplier: dict[str, Any] = {}
    if name:
        supplier["name"] = name
        if email and "@" in email:
            supplier["contact"] = [{"name": name, "email": email}]

    # Collect candidate URLs.
    urls = []
    homepage = (info.get("home_page") or "").strip()
    if homepage.startswith("http"):
        urls.append(homepage)

    project_urls = info.get("project_urls") or {}
    if isinstance(project_urls, dict):
        for k, v in project_urls.items():
            if not isinstance(v, str):
                continue
            if v.startswith("http") and v not in urls and k.lower() in {"homepage", "repository", "source"}:
                urls.append(v)
    if urls:
        supplier["url"] = urls[:3]

    return supplier or None


def _derive_supplier_from_purl(purl: str, name: str, pypi_client: PyPIClient) -> dict[str, Any] | None:
    """Derive supplier info based on the purl string.

    Currently only handles PyPI packages. Stubs left for future ecosystems.
    """
    if not purl:
        return None

    if "pkg:pypi/" in purl:
        # Normalize name for lookup (strip potential version spec parts if present in component name)
        norm_name = re.sub(r"[<>=!].*", "", name).strip()
        meta = pypi_client.get_package(norm_name)
        if meta:
            return _extract_pypi_supplier(meta)
        return None

    # Placeholder examples for potential future support.
    if "pkg:npm/" in purl:
        return {"name": "npm Registry", "url": ["https://www.npmjs.com/"]}
    if "pkg:maven/" in purl:
        return {"name": "Maven Central", "url": ["https://search.maven.org/"]}

    return None


def _enrich_component(component: dict[str, Any], pypi_client: PyPIClient) -> bool:
    """Attempt to add a 'supplier' field to a component; return True if added."""
    if "supplier" in component:
        return False
    name = component.get("name", "")
    purl = component.get("purl", "")
    supplier = _derive_supplier_from_purl(purl, name, pypi_client)
    if supplier:
        component["supplier"] = supplier
        return True
    return False


def enrich_sbom(in_path: Path, out_path: Path, request_delay: float) -> int:
    """Enrich a CycloneDX SBOM in JSON form with supplier information.

    Parameters
    ----------
    in_path : Path
        Path to existing SBOM JSON file.
    out_path : Path
        Destination path for updated SBOM (may equal in_path for in-place).
    request_delay : float
        Delay between outbound registry calls in seconds.

    Returns
    -------
    int
        Count of components updated (including top-level component if applicable).

    Raises
    ------
    FileNotFoundError
        If the SBOM file does not exist.
    json.JSONDecodeError
        If the SBOM file is not valid JSON.
    """
    with in_path.open(encoding="utf-8") as fh:
        sbom = json.load(fh)

    updated = 0
    pypi_client = PyPIClient(request_delay=request_delay)

    components = sbom.get("components")
    if isinstance(components, list):
        for comp in components:
            if isinstance(comp, dict) and _enrich_component(comp, pypi_client):
                updated += 1

    metadata = sbom.get("metadata")
    if isinstance(metadata, dict):
        meta_comp = metadata.get("component")
        if isinstance(meta_comp, dict) and _enrich_component(meta_comp, pypi_client):
            updated += 1

    # Write output
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(sbom, fh, indent=2, ensure_ascii=False)

    return updated


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich a CycloneDX SBOM with supplier data (PyPI based)")
    parser.add_argument("-i", "--input", required=True, help="Path to input SBOM JSON file")
    parser.add_argument("-o", "--output", help="Path for enriched SBOM (defaults to overwrite input)")
    parser.add_argument("--delay", type=float, default=_DEFAULT_REQUEST_DELAY_SEC, help=f"Delay between registry requests in seconds (default: {_DEFAULT_REQUEST_DELAY_SEC})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (DEBUG) logging")
    return parser.parse_args(argv)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    _configure_logging(args.verbose)

    in_path = Path(args.input)
    out_path = Path(args.output) if args.output else in_path

    if not in_path.is_file():
        _LOGGER.error("Input SBOM file not found: %s", in_path)
        return 2

    try:
        updated = enrich_sbom(in_path, out_path, args.delay)
    except FileNotFoundError:
        _LOGGER.error("Input SBOM file not found: %s", in_path)
        return 2
    except json.JSONDecodeError as exc:
        _LOGGER.error("Invalid JSON in SBOM file %s: %s", in_path, exc)
        return 2
    except Exception as exc:  # broad by design as last resort
        _LOGGER.exception("Unexpected error enriching SBOM: %s", exc)
        return 3

    _LOGGER.info("Supplier enrichment complete. Components updated: %d", updated)
    _LOGGER.info("Written SBOM: %s", out_path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
