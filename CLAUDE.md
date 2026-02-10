# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

octodns-exoscale is an [octoDNS](https://github.com/octodns/octodns) provider for [Exoscale](https://www.exoscale.com/) DNS. It implements `ExoscaleProvider` (subclass of `BaseProvider`) that reads/writes DNS records via the Exoscale API v2.

## Development Setup

```bash
pip install -e ".[dev]"
```

## Common Commands

```bash
# Run tests
pytest

# Run a single test
pytest test/test_main.py::test_populate_A

# Code formatting
black octodns_exoscale/ test/
isort octodns_exoscale/ test/

# Static analysis
pyflakes octodns_exoscale/ test/
```

## Architecture

The entire provider is in `octodns_exoscale/__init__.py`. Key structure:

- **`ExoscaleProvider`** — the octoDNS provider class
  - `__init__(id, auth_key, auth_secret, auth_zone)` — authenticates with Exoscale API via `exoscale.api.v2.Client`
  - `populate(zone)` — reads DNS records from Exoscale into an octoDNS Zone
  - `_apply(plan)` — writes changes (create/update/delete) back to Exoscale
  - `_data_for_<TYPE>()` methods — convert Exoscale API responses to octoDNS record format
  - `_params_for_<TYPE>()` methods — convert octoDNS records to Exoscale API request params
  - Updates are implemented as delete + create

**Supported record types:** A, AAAA, CAA, CNAME, MX, NAPTR, NS, SPF, SRV, SSHFP, TXT

**Exoscale API field conventions:** All record data uses the `content` field (not `target`). Record identification uses the `name` field. API methods: `create_dns_domain_record(**kwargs)`, `delete_dns_domain_record(domain_id, record_id)`, `list_dns_domain_records(domain_id)`, `list_dns_domains()`.

## Configuration

The provider requires three credentials configured in octoDNS YAML:

```yaml
providers:
  exoscale:
    class: octodns_exoscale.ExoscaleProvider
    auth-key: env/EXOSCALE_API_KEY
    auth-secret: env/EXOSCALE_API_SECRET
    auth-zone: ch-dk-2
```