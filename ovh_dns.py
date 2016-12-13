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
author: Albin Kerouanton @NiR-
short_description: Manage OVH DNS records
description:
    - Manage OVH (French European hosting provider) DNS records
version_added: "2.3"
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
        default: 0
        description:
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
        add_record(records, info)

    return records

def add_record(records, info):
    fieldtype = info['fieldType']
    subdomain = info['subDomain']
    targetval = info['target']

    if fieldtype not in records:
        records[fieldtype] = dict()
    if subdomain not in records[fieldtype]:
        records[fieldtype][subdomain] = dict()

    records[fieldtype][subdomain][targetval] = info

def find_record(records, name, fieldtype, targetval):
    if fieldtype not in records:
        return False
    if name not in records[fieldtype]:
        return False
    if targetval not in records[fieldtype][name]:
        return False

    return records[fieldtype][name][targetval]

def ensure_record_present(module, records, client):
    domain    = module.params.get('domain')
    name      = module.params.get('name')
    fieldtype = module.params.get('type')
    targetval = module.params.get('value')
    ttl       = int(module.params.get('ttl'))
    record    = find_record(records, name, fieldtype, targetval)

    # Does the record exist already?
    if record:
        # The record is already as requested, no need to change anything
        if ttl == record['ttl']:
            module.exit_json(changed=False)

        if module.check_mode:
            module.exit_json(changed=True, diff=dict(ttl=ttl))

        try:
            # Delete and re-create the record
            client.delete('/domain/zone/{}/record/{}'.format(domain, record['id']))
            client.post('/domain/zone/{}/record'.format(domain), fieldType=fieldtype, subDomain=name, target=targetval, ttl=ttl)
            client.post('/domain/zone/{}/refresh'.format(domain))
        except APIError as error:
            module.fail_json(
                msg='Unable to call OVH api for recreating the record "{0} {1} {2}". '
                'Error returned by OVH api is: "{3}".'.format(name, fieldtype, targetval, error)
            )

        module.exit_json(changed=True)

    if module.check_mode:
        module.exit_json(changed=True, diff=dict(name=name, type=fieldtype, value=targetval, ttl=ttl))

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

def ensure_record_absent(module, records, client):
    domain    = module.params.get('domain')
    name      = module.params.get('name')
    fieldtype = module.params.get('type')
    targetval = module.params.get('value')
    record    = find_record(records, name, fieldtype, targetval)

    if not record:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    try:
        # Remove the record
        client.delete('/domain/zone/{}/record/{}'.format(domain, record['id']))
        client.post('/domain/zone/{}/refresh'.format(domain))
    except APIError as error:
        module.fail_json(
            msg='Unable to call OVH api for deleting the record "{0}" for "{1}"". '
            'Error returned by OVH api is: "{2}".'.format(name, domain, error)
        )

    module.exit_json(changed=True)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            domain = dict(required=True),
            name = dict(required=True),
            value = dict(required=True),
            type = dict(default='A', choices=['A', 'AAAA', 'CNAME', 'DKIM', 'LOC', 'MX', 'NAPTR', 'NS', 'PTR', 'SPF', 'SRV', 'SSHFP', 'TXT']),
            ttl = dict(default='0'),
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
        ensure_record_absent(module, records, client)
    elif state == 'present':
        ensure_record_present(module, records, client)

    # We should never reach here
    module.fail_json(msg='Internal ovh_dns module error')


# import module snippets
from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()
