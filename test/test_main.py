#!/usr/bin/python3 -B
from octodns.zone import Zone
from octodns_exoscale import ExoscaleProvider


def test_main():
	exoscale_provider = ExoscaleProvider('test_id',"EXOdd7d02f15f08675144fe4992", "-Z1FUDXz1Zk7TqVXHz7fOMkB1rmyMnWN4-rSHOVVSCQ", "ch-dk-2")

	octodns_zone: Zone = Zone('nkr.wtf.', [])
	exoscale_provider.populate(octodns_zone)

	print('zones', exoscale_provider._zones)
	print('records', exoscale_provider._zone_records)


if __name__ == "__main__":
	raise SystemExit(test_main())