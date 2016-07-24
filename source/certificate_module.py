#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: certificate
short_description: Manages server and client certificates.  
description:
    - Creates public, private certificates in PEM and PKCS12 formats
author:
    - "Richard Clayton (@rclayton-the-terrible)"
    - "James Whetsell (@zer0glitch)"
options:
  cadir:
    description:
      - The directory to store the certificate
    required: true
  certname:
    description:
      - The CN (common name) for the certificate
    required: true
  subj:
    description:
      - The full subject path for the certificate
    required: true
  p12password:
    description:
      - The password for the PKCS12 certificate
    required: true
  state:
    description:
      - To create or remove the CA. Present or absent: default is present.
    required: false
  subjectAltNames:
    description:
      - Alternative names for the certificate.  Can be DNS, IP, etc.
    required: false
requirements: [ openssl ]
'''

EXAMPLES = '''
- name: Create a Server Cert
  certificate: cadir="/etc/certs" hostname="server.example.com" subj="/DC=com/DC=example/CN=server/" p12password="{{some_env_var}}"

- name: Create a Client Cert
  certificate: cadir="/etc/certs" hostname="client.example.com" subj="/DC=com/DC=example/CN=client/" p12password="{{some_env_var}}" certtype="client"

- name: Remove a Server Cert
  certificate: cadir="/etc/certs" hostname="server.example.com" subj="doesn't matter" p12password="blah!" state="absent"
'''

from certificate import Certificate

def main():

    BASE_MODULE_ARGS = dict(
        cadir = dict(default="/etc/certs"),
        certname = dict(required=True),
        subj = dict(default="/DC=com/DC=example/CN=CA/"),
        p12password = dict(required=True),
        certtype = dict(default="server", choices=["server", "client"]),
        state = dict(default="present", choices=["present", "absent"]),
        subjectAltNames = dict(required=False)
    )

    module = AnsibleModule(
        argument_spec= BASE_MODULE_ARGS,
        supports_check_mode=True
    )

    isServerCert = True

    if module.params["certtype"] == "client":
        isServerCert = False

    # cadir, certname, subj, p12password, isServerCert
    cert = Certificate(
        module.params["cadir"],
        module.params["certname"],
        module.params["subj"],
        module.params["p12password"],
        isServerCert,
        module.params["subjectAltNames"]
    )

    isValid = cert.validate_config()

    if isValid["success"]:
        if module.params["state"] == "present":
            isValid = cert.create_certificate()
        else:
            isValid = cert.remove_certificate()

    if not isValid["success"]:
        module.fail_json(msg=isValid["msg"])
    else:
        module.exit_json(**isValid)


# this is magic, see lib/ansible/module_common.py
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>
main()
