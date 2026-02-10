from unittest.mock import MagicMock, patch

from octodns.provider.plan import Plan
from octodns.record import Record
from octodns.record.change import Create, Delete, Update
from octodns.zone import Zone

from octodns_exoscale import ExoscaleProvider

ZONE_NAME = 'example.com.'
ZONE_ID = 'zone-id-123'

DOMAIN_LIST = {
    'dns-domains': [
        {'id': ZONE_ID, 'unicode-name': 'example.com'},
    ]
}


def _get_provider(mock_client):
    with patch('octodns_exoscale.Client', return_value=mock_client):
        return ExoscaleProvider(
            'test', 'fake-key', 'fake-secret', 'ch-gva-2'
        )


def _get_zone():
    return Zone(ZONE_NAME, [])


def _populate(mock_client, api_records):
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': api_records,
    }
    provider = _get_provider(mock_client)
    zone = _get_zone()
    provider.populate(zone)
    return zone


# --- Fixtures: Exoscale API responses ---

API_RECORDS = [
    {
        'id': 'r-a-1',
        'name': 'www',
        'type': 'A',
        'content': '1.2.3.4',
        'ttl': 300,
    },
    {
        'id': 'r-a-2',
        'name': 'www',
        'type': 'A',
        'content': '5.6.7.8',
        'ttl': 300,
    },
    {
        'id': 'r-aaaa-1',
        'name': 'ipv6',
        'type': 'AAAA',
        'content': '2001:db8::1',
        'ttl': 300,
    },
    {
        'id': 'r-caa-1',
        'name': '.',
        'type': 'CAA',
        'content': '0 issue "letsencrypt.org"',
        'ttl': 300,
    },
    {
        'id': 'r-cname-1',
        'name': 'alias',
        'type': 'CNAME',
        'content': 'www.example.com',
        'ttl': 300,
    },
    {
        'id': 'r-mx-1',
        'name': '.',
        'type': 'MX',
        'content': 'mail.example.com',
        'priority': 10,
        'ttl': 300,
    },
    {
        'id': 'r-ns-1',
        'name': '.',
        'type': 'NS',
        'content': 'ns1.example.com',
        'ttl': 3600,
    },
    {
        'id': 'r-srv-1',
        'name': '_sip._tcp',
        'type': 'SRV',
        'content': '60 5060 sip.example.com',
        'priority': 10,
        'ttl': 300,
    },
    {
        'id': 'r-naptr-1',
        'name': '.',
        'type': 'NAPTR',
        'content': '10 100 "s" "SIP+D2U" "" _sip._udp.example.com.',
        'ttl': 300,
    },
    {
        'id': 'r-sshfp-1',
        'name': '.',
        'type': 'SSHFP',
        'content': '1 1 AABBCCDD',
        'ttl': 300,
    },
    {
        'id': 'r-txt-1',
        'name': '.',
        'type': 'TXT',
        'content': 'v=spf1 include:example.com ~all',
        'ttl': 300,
    },
]


# --- Tests: zones property ---


def test_zones():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    provider = _get_provider(mock_client)

    zones = provider.zones
    assert ZONE_NAME in zones
    assert zones[ZONE_NAME]['id'] == ZONE_ID
    mock_client.list_dns_domains.assert_called_once()


def test_zones_cached():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    provider = _get_provider(mock_client)

    provider.zones
    provider.zones
    mock_client.list_dns_domains.assert_called_once()


# --- Tests: populate ---


def test_populate_A():
    zone = _populate(MagicMock(), [r for r in API_RECORDS if r['type'] == 'A'])
    record = list(zone.records)[0]
    assert record._type == 'A'
    assert record.name == 'www'
    assert sorted(record.values) == ['1.2.3.4', '5.6.7.8']
    assert record.ttl == 300


def test_populate_AAAA():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'AAAA']
    )
    record = list(zone.records)[0]
    assert record._type == 'AAAA'
    assert record.name == 'ipv6'
    assert list(record.values) == ['2001:db8::1']


def test_populate_CAA():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'CAA']
    )
    record = list(zone.records)[0]
    assert record._type == 'CAA'
    assert record.name == ''
    values = list(record.values)
    assert values[0].flags == 0
    assert values[0].tag == 'issue'
    assert values[0].value == 'letsencrypt.org'


def test_populate_CNAME():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'CNAME']
    )
    record = list(zone.records)[0]
    assert record._type == 'CNAME'
    assert record.name == 'alias'
    assert record.value == 'www.example.com.'


def test_populate_MX():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'MX']
    )
    record = list(zone.records)[0]
    assert record._type == 'MX'
    values = list(record.values)
    assert values[0].preference == 10
    assert values[0].exchange == 'mail.example.com.'


def test_populate_NS():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'NS']
    )
    assert zone.root_ns is not None
    values = list(zone.root_ns.values)
    assert 'ns1.example.com.' in values


def test_populate_SRV():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'SRV']
    )
    record = list(zone.records)[0]
    assert record._type == 'SRV'
    values = list(record.values)
    assert values[0].priority == 10
    assert values[0].weight == 60
    assert values[0].port == 5060
    assert values[0].target == 'sip.example.com.'


def test_populate_NAPTR():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'NAPTR']
    )
    record = list(zone.records)[0]
    assert record._type == 'NAPTR'
    values = list(record.values)
    assert values[0].order == 10
    assert values[0].preference == 100
    assert values[0].flags == 'S'
    assert values[0].service == 'SIP+D2U'
    assert values[0].regexp == ''
    assert values[0].replacement == '_sip._udp.example.com.'


def test_populate_SSHFP():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'SSHFP']
    )
    record = list(zone.records)[0]
    assert record._type == 'SSHFP'
    values = list(record.values)
    assert values[0].algorithm == 1
    assert values[0].fingerprint_type == 1
    assert values[0].fingerprint == 'aabbccdd'


def test_populate_TXT():
    zone = _populate(
        MagicMock(), [r for r in API_RECORDS if r['type'] == 'TXT']
    )
    record = list(zone.records)[0]
    assert record._type == 'TXT'
    assert 'v=spf1 include:example.com ~all' in list(record.values)


def test_populate_skips_unsupported():
    unsupported = {
        'id': 'r-ptr-1',
        'name': '4.3.2.1',
        'type': 'PTR',
        'content': 'host.example.com',
        'ttl': 300,
    }
    zone = _populate(MagicMock(), [unsupported])
    assert len(zone.records) == 0


def test_populate_all_record_types():
    zone = _populate(MagicMock(), API_RECORDS)
    type_names = {r._type for r in zone.records}
    # Root NS ends up in zone.root_ns, not zone.records
    expected = {
        'A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'SRV', 'SSHFP',
        'TXT',
    }
    assert type_names == expected
    assert zone.root_ns is not None


def test_populate_txt_with_semicolon():
    records = [
        {
            'id': 'r-txt-sc',
            'name': '_dmarc',
            'type': 'TXT',
            'content': 'v=DMARC1; p=none; rua=mailto:d@example.com',
            'ttl': 300,
        },
    ]
    zone = _populate(MagicMock(), records)
    record = list(zone.records)[0]
    values = list(record.values)
    assert 'v=DMARC1\\; p=none\\; rua=mailto:d@example.com' in values


# --- Tests: _apply create ---


def test_apply_create_A():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    record = Record.new(
        zone, 'www', {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4', '5.6.7.8']}
    )

    change = Create(record)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    assert mock_client.create_dns_domain_record.call_count == 2
    mock_client.create_dns_domain_record.assert_any_call(
        domain_id=ZONE_ID,
        name='www',
        type='A',
        content='1.2.3.4',
        ttl=300,
    )
    mock_client.create_dns_domain_record.assert_any_call(
        domain_id=ZONE_ID,
        name='www',
        type='A',
        content='5.6.7.8',
        ttl=300,
    )


def test_apply_create_root_record():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    record = Record.new(
        zone, '', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
    )

    change = Create(record)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    mock_client.create_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID,
        name='',
        type='A',
        content='1.2.3.4',
        ttl=300,
    )


def test_apply_create_CNAME():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    record = Record.new(
        zone,
        'alias',
        {'type': 'CNAME', 'ttl': 300, 'value': 'www.example.com.'},
    )

    change = Create(record)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    mock_client.create_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID,
        name='alias',
        type='CNAME',
        content='www.example.com.',
        ttl=300,
    )


def test_apply_create_MX():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    record = Record.new(
        zone,
        '',
        {
            'type': 'MX',
            'ttl': 300,
            'values': [{'priority': 10, 'exchange': 'mail.example.com.'}],
        },
    )

    change = Create(record)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    mock_client.create_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID,
        name='',
        type='MX',
        content='10 mail.example.com.',
        ttl=300,
    )


def test_apply_create_SRV():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    record = Record.new(
        zone,
        '_sip._tcp',
        {
            'type': 'SRV',
            'ttl': 300,
            'values': [
                {
                    'priority': 10,
                    'weight': 60,
                    'port': 5060,
                    'target': 'sip.example.com.',
                }
            ],
        },
    )

    change = Create(record)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    mock_client.create_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID,
        name='_sip._tcp',
        type='SRV',
        content='60 5060 sip.example.com.',
        ttl=300,
        priority=10,
    )


# --- Tests: _apply delete ---


def test_apply_delete():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [
            {
                'id': 'r-a-1',
                'name': 'www',
                'type': 'A',
                'content': '1.2.3.4',
                'ttl': 300,
            },
            {
                'id': 'r-a-2',
                'name': 'www',
                'type': 'A',
                'content': '5.6.7.8',
                'ttl': 300,
            },
        ],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    provider.populate(zone)

    existing = Record.new(
        zone,
        'www',
        {'type': 'A', 'ttl': 300, 'values': ['1.2.3.4', '5.6.7.8']},
    )

    change = Delete(existing)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    assert mock_client.delete_dns_domain_record.call_count == 2
    mock_client.delete_dns_domain_record.assert_any_call(
        domain_id=ZONE_ID, record_id='r-a-1'
    )
    mock_client.delete_dns_domain_record.assert_any_call(
        domain_id=ZONE_ID, record_id='r-a-2'
    )


def test_apply_delete_only_matches_name_and_type():
    """Delete should only remove records matching both name and type."""
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [
            {
                'id': 'r-a-1',
                'name': 'www',
                'type': 'A',
                'content': '1.2.3.4',
                'ttl': 300,
            },
            {
                'id': 'r-txt-1',
                'name': 'www',
                'type': 'TXT',
                'content': 'some text',
                'ttl': 300,
            },
        ],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    provider.populate(zone)

    existing = Record.new(
        zone, 'www', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
    )

    change = Delete(existing)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    mock_client.delete_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID, record_id='r-a-1'
    )


# --- Tests: _apply update ---


def test_apply_update():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [
            {
                'id': 'r-a-1',
                'name': 'www',
                'type': 'A',
                'content': '1.2.3.4',
                'ttl': 300,
            },
        ],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    provider.populate(zone)

    existing = Record.new(
        zone, 'www', {'type': 'A', 'ttl': 300, 'value': '1.2.3.4'}
    )
    new = Record.new(
        zone, 'www', {'type': 'A', 'ttl': 300, 'value': '9.8.7.6'}
    )

    change = Update(existing, new)
    plan = Plan(zone, zone, [change], True)
    provider._apply(plan)

    # Delete old
    mock_client.delete_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID, record_id='r-a-1'
    )
    # Create new
    mock_client.create_dns_domain_record.assert_called_once_with(
        domain_id=ZONE_ID,
        name='www',
        type='A',
        content='9.8.7.6',
        ttl=300,
    )


# --- Tests: cache behavior ---


def test_apply_clears_zone_record_cache():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    provider.populate(zone)
    assert ZONE_NAME in provider._zone_records

    plan = Plan(zone, zone, [], True)
    provider._apply(plan)
    assert ZONE_NAME not in provider._zone_records


def test_zone_records_cached():
    mock_client = MagicMock()
    mock_client.list_dns_domains.return_value = DOMAIN_LIST
    mock_client.list_dns_domain_records.return_value = {
        'dns-domain-records': [],
    }
    provider = _get_provider(mock_client)

    zone = _get_zone()
    provider.populate(zone)
    provider.populate(zone)
    mock_client.list_dns_domain_records.assert_called_once()