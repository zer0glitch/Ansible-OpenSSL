#!/usr/bin/python
# -*- coding: utf-8 -*-


DOCUMENTATION = '''
---
module: ca
short_description: Manages CA certificates
description:
    - Create, update, and delete for a CA
author:
    - "Richard Clayton (@rclayton-the-terrible)"
    - "James Whetsell (@zer0glitch)"
options:
  certdir:
    description:
      - The directory to store the certificate
    required: true
  subj:
    description:
      - The CA subject
    required: true
  state:
    description:
      - To create or remove the CA. Present or absent: default is present.
    required: false
  force:
    description:
      - This will overwrite the CA
    required: false
requirements: [ openssl ]
'''

EXAMPLES = '''

- name: Setup a CA
  ca: certdir="/etc/certs" subj="/DC=com/DC=example/CN=CA/"
- name: Remove a CA
  ca: certdir="/etc/certs" subj="/CN=whatever/" state="absent"
'''

from ca import CA

def main():

    BASE_MODULE_ARGS = dict(
        certdir = dict(default="/etc/certs"),
        subj = dict(default="/DC=com/DC=example/CN=CA/"),
        state = dict(default="present", choices=["present", "absent"]),
        force = dict(default="false", choices=["true", "false"])
    )

    module = AnsibleModule(
        argument_spec= BASE_MODULE_ARGS,
        supports_check_mode=True
    )

    ca = CA(module.params["certdir"], module.params["subj"], module.params["force"])

    if not ca.force:
       if ca.check_if_ca_exists():
         module.exit_json(dict(changed=false, skip_reason="Conditional check failed", skipped=true));

    isValid = ca.validate_setup()

    if isValid["success"]:
        if module.params["state"] == "present":
            isValid = ca.setup()
        else:
            isValid = ca.removeCA()

    if not isValid["success"]:
        module.fail_json(msg=isValid["msg"])
    else:
        module.exit_json(**isValid)


# this is magic, see lib/ansible/module_common.py
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>
main()
