#!/usr/bin/python
# -*- coding: utf-8 -*-

# ovh_dns, an Ansible module for managing OVH DNS records
# Copyright (C) 2014, Carlos Izquierdo <gheesh@gheesh.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

DOCUMENTATION = '''
---
module: ovh_dns
author: Carlos Izquierdo
short_description: Manage OVH DNS records
description:
    - Manage OVH (French European hosting provider) DNS records

notes:
    - Uses the python OVH Api U(https://github.com/ovh/python-ovh).
      You have to create an application (a key and secret) with a consummer
      key as described into U(https://eu.api.ovh.com/g934.first_step_with_api)
requirements: [ "ovh" ]
options:
    domain:
        required: true
        description:
            - Name of the domain zone
    name:
        required: true
        description:
            - Name of the DNS record
    value:
        required: true
        description:
            - Value of the DNS record (i.e. what it points to)
    type:
        default: A
        choices: ['A', 'AAAA', 'CNAME', 'DKIM', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SPF', 'SRV', 'SSHFP', 'TXT']
        description:
            - Type of DNS record (A, AAAA, PTR, CNAME, etc.)
    ttl:
        decription:
            - Time to live of the DNS record
    state:
        default: present
        choices: ['present', 'absent']
        description:
            - Determines wether the record is to be created/modified or deleted
    endpoint:
        required: true
        description:
            - The endpoint to use ( for instance ovh-eu)
    application_key:
        required: true
        description:
            - The applicationKey to use
    application_secret:
        required: true
        description:
            - The application secret to use
    consumer_key:
        required: true
        description:
            - The consumer key to use
'''

EXAMPLES = '''
# Create a typical A record
- ovh_dns:
    state: present
    domain: mydomain.com
    name: db1
    value: 10.10.10.10
    ttl: 3600
    endpoint: ovh-eu
    application_key: yourkey
    application_secret: yoursecret
    consumer_key: yourconsumerkey

# Create a CNAME record
- ovh_dns:
    state: present
    domain: mydomain.com
    name: dbprod
    type: CNAME
    value: db1
    ttl: 3600
    endpoint: ovh-eu
    application_key: yourkey
    application_secret: yoursecret
    consumer_key: yourconsumerkey

# Delete an existing record, must specify all parameters
- ovh_dns:
    state: absent
    domain: mydomain.com
    name: dbprod
    type: CNAME
    value: db1
    endpoint: ovh-eu
    application_key: yourkey
    application_secret: yoursecret
    consumer_key: yourconsumerkey
'''

RETURN='''
'''

import os
import sys

try:
    import ovh
    from ovh.exceptions import APIError
    HAS_OVH=True
except ImportError:
    HAS_OVH=False

def get_ovh_client(module):
    endpoint = module.params.get('endpoint')
    application_key = module.params.get('application_key')
    application_secret = module.params.get('application_secret')
    consumer_key = module.params.get('consumer_key')

    return ovh.Client(
        endpoint=endpoint,
        application_key=application_key,
        application_secret=application_secret,
        consumer_key=consumer_key
    )


def get_domain_records(client, domain):
    """Obtain all records for a specific domain"""
    records = {}

    # List all ids and then get info for each one
    record_ids = client.get('/domain/zone/{}/record'.format(domain))

    for record_id in record_ids:
        info = client.get('/domain/zone/{}/record/{}'.format(domain, record_id))
        # TODO: Cannot aggregate based only on name, must use record type and target as well
        records[info['subDomain']] = info

    return records

def compute_diff(record, name, fieldtype, targetval, ttl):
    diff = {
        'name': 'subDomain' in record and record['subDomain'] != name and name or False,
        'type': 'fieldType' in record and record['fieldType'] != fieldtype and fieldtype or False,
        'value': 'target' in record and record['target'] != targetval and targetval or False,
        'ttl': 'ttl' in record and record['ttl'] != ttl and ttl or False
    }

    return dict((key, val) for (key, val) in diff.iteritems() if val)

def ensure_record_present(module, records, client, domain, name):
    fieldtype = module.params.get('type')
    targetval = module.params.get('value')
    ttl = int(module.params.get('ttl'))

    # Since we are inserting a record, we need a target
    if targetval == '':
        module.fail_json(msg='Did not specify a value')

    # Does the record exist already?
    if name in records:
        record = records[name]
        diff   = compute_diff(record, name, fieldtype, targetval, ttl)

        if len(diff) == 0:
            # The record is already as requested, no need to change anything
            module.exit_json(changed=False)

        if module.check_mode:
            module.exit_json(changed=True, diff=diff)

        try:
            # Delete and re-create the record
            client.delete('/domain/zone/{}/record/{}'.format(domain, records[name]['id']))
            client.post('/domain/zone/{}/record'.format(domain), fieldType=fieldtype, subDomain=name, target=targetval, ttl=ttl)
            client.post('/domain/zone/{}/refresh'.format(domain))
        except APIError as error:
            module.fail_json(
                msg='Unable to call OVH api for recreating the record "{0} {1} {2}". '
                'Error returned by OVH api is: "{3}".'.format(name, fieldtype, targetval, error)
            )

        module.exit_json(changed=True)

    if module.check_mode:
        module.exit_json(changed=True, diff=compute_diff(record, name, fieldtype, targetval, ttl))

    try:
        # Add the record
        client.post('/domain/zone/{}/record'.format(domain), fieldType=fieldtype, subDomain=name, target=targetval, ttl=ttl)
        client.post('/domain/zone/{}/refresh'.format(domain))
    except APIError as error:
        module.fail_json(
            msg='Unable to call OVH api for adding the record "{0} {1} {2}". '
            'Error returned by OVH api is: "{3}".'.format(name, fieldtype, targetval, error)
        )

    module.exit_json(changed=True)

def ensure_record_absent(module, records, client, domain, name):
    # Are we done yet?
    #if name not in records or records[name]['fieldType'] != fieldtype or records[name]['target'] != targetval:
    if name not in records:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    try:
        # Remove the record
        # TODO: Must check parameters
        client.delete('/domain/zone/{}/record/{}'.format(domain, records[name]['id']))
        client.post('/domain/zone/{}/refresh'.format(domain))
    except APIError as error:
        module.fail_json(
            msg='Unable to call OVH api for deleting the record "{0}" for "{1}"". '
            'Error returned by OVH api is: "{2}".'.format(name, domain, error)
        )

    module.exit_json(changed=True)

# @TODO: Add support for check_mode
def main():
    module = AnsibleModule(
        argument_spec = dict(
            domain = dict(required=True),
            name = dict(required=True),
            value = dict(default=''),
            type = dict(default='A', choices=['A', 'AAAA', 'CNAME', 'DKIM', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SPF', 'SRV', 'SSHFP', 'TXT']),
            ttl = dict(required=False),
            state = dict(default='present', choices=['present', 'absent']),
            endpoint = dict(required=True),
            application_key = dict(required=True, no_log=True),
            application_secret = dict(required=True, no_log=True),
            consumer_key = dict(required=True, no_log=True),
        ),
        supports_check_mode=True
    )

    if not HAS_OVH:
        module.fail_json(msg='ovh python module is required to run this module.')

    # Get parameters
    domain = module.params.get('domain')
    name   = module.params.get('name')
    state  = module.params.get('state')

    client = get_ovh_client(module)

    try:
        # Check that the domain exists
        domains = client.get('/domain/zone')
    except APIError as error:
        module.fail_json(
            msg='Unable to call OVH api for getting the list of domains. '
            'Check application key, secret, consumer key & parameters. '
            'Error returned by OVH api is: "{0}".'.format(error)
        )

    if not domain in domains:
        module.fail_json(msg='Domain {} does not exist'.format(domain))

    try:
        # Obtain all domain records to check status against what is demanded
        records = get_domain_records(client, domain)
    except APIError as error:
        module.fail_json(
            msg='Unable to call OVH api for getting the list of records for "{0}". '
            'Error returned by OVH api is: "{1}".'.format(domain, error)
        )

    if state == 'absent':
        ensure_record_absent(module, records, client, domain, name)
    elif state == 'present':
        ensure_record_present(module, records, client, domain, name)

    # We should never reach here
    module.fail_json(msg='Internal ovh_dns module error')


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
