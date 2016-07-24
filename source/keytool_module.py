#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: keytool
short_description: Manages keystores and truststores for java
description:
    - Creates and Manages java keystores and truststores
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
  store_password:
    description:
      - The password for the store
    required: true
  host_to_trust:
    description:
      - A list of hsots to add to the truststore
    required: false
  state:
    description:
      - To create or remove the CA. Present or absent: default is present.
    required: false
  certtype:
    description:
      - The certificate type.  Values: keystore or truststore
    required: false
  src_password:
    description:
      - Source password for the PKCS12 certificate that is being imported
    required: false
requirements: [ openssl ]
'''

EXAMPLES = '''
- name: Create a java server trustore and trust the server hosts
  keytool: cadir="/etc/certs" certname="host1.example.com" store_password='changeit' hosts_to_trust="host1.example.com"

  - name: Create a java server keystore 
    keytool: cadir="/etc/certs" certname="host1.example.com" store_password='changeit'  certtype="keystore" src_password='changeit'
'''


from keytool import Keytool

def main():

    BASE_MODULE_ARGS = dict(
        cadir = dict(default="/etc/certs"),
        certname = dict(required=True),
        store_password = dict(required=True),
        hosts_to_trust = dict(required=False, type="list"),
        state = dict(default="present", choices=["present", "absent"]),
        certtype = dict(required=False, default="truststore", choices=["truststore","keystore"]),
        src_password = dict(required=False)
    )

    module = AnsibleModule(
        argument_spec= BASE_MODULE_ARGS,
        supports_check_mode=True
    )

    keytool = Keytool(
        module.params["cadir"],
        module.params["certname"],
        module.params["store_password"],
        module.params["hosts_to_trust"],
        module.params["certtype"],
        module.params["src_password"],
    )

    isValid = keytool.validate()

    if isValid["success"]:
        if module.params["state"] == "present":
            isValid = keytool.build_trust_store()
        else:
            isValid = keytool.remove_trust_store()

    if not isValid["success"]:
        module.fail_json(msg=isValid["msg"])
    else:
        module.exit_json(**isValid)


# this is magic, see lib/ansible/module_common.py
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>
main()
