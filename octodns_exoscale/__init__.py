from typing import Any, Union, Iterator
import logging
from collections import defaultdict

from octodns.idna import IdnaDict
from octodns.zone import Zone
from octodns.record import (
    ARecord,
    AaaaRecord,
    CaaRecord,
    Change,
    CnameRecord,
    MxRecord,
    NaptrRecord,
    NsRecord,
    Record,
    SpfRecord,
    SrvRecord,
    SshfpRecord,
    TxtRecord,
)

from octodns.provider.base import BaseProvider, Plan


from exoscale.api.v2 import Client

__version__ = __VERSION__ = "0.0.1"


class ExoscaleProvider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_ROOT_NS = True
    SUPPORTS_POOL_VALUE_STATUS = False
    SUPPORTS = set(
        (
            "A",
            "AAAA",
            "CAA",
            "CNAME",
            "MX",
            "NAPTR",
            "NS",
            "SPF",
            "SRV",
            "SSHFP",
            "TXT",
        )
    )

    def __init__(self, id: str, auth_key: str, auth_secret: str, auth_zone: str, *args, **kwargs):
        self.log = logging.getLogger(f"ExoscaleProvider[{id}]")
        self.log.debug("__init__: id=%s, key=%s", id, auth_key)
        super().__init__(id, *args, **kwargs)
        self._client = Client(auth_key, auth_secret, zone=auth_zone)

        self._zones = None
        self._zone_records = {}

    @property
    def zones(self):
        if self._zones is None:
            dns_domains_list = self._client.list_dns_domains()
            self._zones = IdnaDict(
                {f'{z["unicode-name"]}.': {"id": z["id"]} for z in dns_domains_list["dns-domains"]}
            )
        return self._zones

    def _get_zone_without_trailling_dot(self, zone: str) -> str:
        return zone.rstrip(".")

    def _get_fqdn(self, name: str) -> str:
        return name if name.endswith(".") else f"{name}."

    def _get_record_name(self, record_name: str) -> str:
        return record_name if record_name else "."

    def populate(self, zone: Zone, target: bool = False, lenient: bool = False) -> bool:
        self.log.debug(
            "populate: name=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))

        for record in self.zone_records(zone):
            _type = record["type"]
            _name = record["name"]

            if _type not in self.SUPPORTS:
                self.log.warning(f"populate: skipping unsupported {_type} {_name}.{zone} record")
                continue
            values[_name][_type].append(record)

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f"_data_for_{_type}")

                if name == ".":
                    name = ""

                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            "populate:   found %s records, exists=%s",
            len(zone.records) - before,
            exists,
        )

        return exists

    def zone_records(self, zone: Zone) -> list[dict[str, Any]]:
        if zone.name not in self._zone_records:
            self._zone_records[zone.name] = self._client.list_dns_domain_records(
                domain_id=self.zones[zone.name]["id"]
            )["dns-domain-records"]

        return self._zone_records[zone.name]

    def _data_for_multiple(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [record["content"].replace(";", "\\;") for record in records],
        }

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_TXT = _data_for_multiple

    def _data_for_CAA(
        self, _type: str, records: list[dict[str, str]]
    ) -> dict[str, Union[str, int, list]]:
        values = []
        for record in records:
            flags, tag, value = record["content"].split(" ", 2)
            values.append({"flags": int(flags), "tag": tag, "value": value.replace('"', "")})

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_CNAME(self, _type, records):
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "value": self._get_fqdn(records[0]["content"]),
        }

    def _data_for_MX(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            values.append(
                {
                    "priority": record["priority"],
                    "exchange": self._get_fqdn(record["content"]),
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_NS(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "ttl": records[0]["ttl"],
            "type": _type,
            "values": [self._get_fqdn(record["content"]) for record in records],
        }

    def _data_for_SRV(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            weight, port, target = record["content"].split(" ", 2)
            values.append(
                {
                    "priority": record["priority"],
                    "weight": int(weight),
                    "port": int(port),
                    "target": self._get_fqdn(target),
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_NAPTR(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            order, preference, flags, service, regexp, replacement = record["content"].split(" ", 5)
            values.append(
                {
                    "order": int(order),
                    "preference": int(preference),
                    "flags": flags.replace('"', "").upper(),
                    "service": service.replace('"', ""),
                    "regexp": regexp.replace('"', ""),
                    "replacement": replacement,
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _data_for_SSHFP(self, _type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        values = []
        for record in records:
            algorithm, fingerprint_type, fingerprint = record["content"].split(" ", 2)
            values.append(
                {
                    "algorithm": int(algorithm),
                    "fingerprint_type": int(fingerprint_type),
                    "fingerprint": fingerprint.lower(),
                }
            )

        return {"ttl": records[0]["ttl"], "type": _type, "values": values}

    def _params_for_multiple(
        self, record: Union[ARecord, AaaaRecord, NsRecord, TxtRecord]
    ) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": self._get_record_name(record.name),
                "content": value.replace("\\;", ";"),
                "ttl": record.ttl,
                "type": record._type,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple
    _params_for_NS = _params_for_multiple
    _params_for_TXT = _params_for_multiple

    def _params_for_CAA(self, record: CaaRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": self._get_record_name(record.name),
                "content": f'{value.flags} {value.tag} "{value.value}"',
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_CNAME(self, record: CnameRecord) -> Iterator[dict[str, Any]]:
        yield {
            "name": self._get_record_name(record.name),
            "content": record.value,
            "ttl": record.ttl,
            "type": record._type,
        }

    def _params_for_MX(self, record: MxRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": self._get_record_name(record.name),
                "content": f"{value.preference} {value.exchange}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_SRV(self, record: SrvRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": self._get_record_name(record.name),
                "priority": value.priority,
                "content": f"{value.weight} {value.port} {value.target}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_NAPTR(self, record: SrvRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": self._get_record_name(record.name),
                "content": f'{value.order} {value.preference} "{value.flags.lower()}" "{value.service}" "{value.regexp}" {value.replacement}',
                "ttl": record.ttl,
                "type": record._type,
            }

    def _params_for_SSHFP(self, record: SshfpRecord) -> Iterator[dict[str, Any]]:
        for value in record.values:
            yield {
                "name": self._get_record_name(record.name),
                "content": f"{value.algorithm} {value.fingerprint_type} {value.fingerprint}",
                "ttl": record.ttl,
                "type": record._type,
            }

    def _apply_create(self, changes: Change):
        new = changes.new
        params_for = getattr(self, f"_params_for_{new._type}")

        for param in params_for(new):
            if param["name"] == ".":
                param["name"] = ""

            kwargs = {
                "domain_id": self.zones[new.zone.name]["id"],
                "name": param["name"],
                "type": param["type"],
                "content": param["content"],
                "ttl": param["ttl"],
            }

            if "priority" in param:
                kwargs["priority"] = param["priority"]

            self._client.create_dns_domain_record(**kwargs)

    def _apply_delete(self, changes: Change):
        existing = changes.existing
        zone = existing.zone

        for record in self.zone_records(zone):
            name = existing.name
            if name == record["name"] and existing._type == record["type"]:
                self._client.delete_dns_domain_record(
                    domain_id=self.zones[existing.zone.name]["id"],
                    record_id=record["id"],
                )

    def _apply_update(self, changes: Change):
        self._apply_delete(changes)
        self._apply_create(changes)

    def _apply(self, plan: Plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug("_apply: zone=%s, len(changes)=%d", desired.name, len(changes))

        for change in changes:
            class_name = change.__class__.__name__.lower()
            self.log.info(change)
            getattr(self, f"_apply_{class_name}")(change)

        self._zone_records.pop(desired.name, None)
