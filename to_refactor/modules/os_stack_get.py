# (c) 2017, Tristan Cacqueray <tdecacqu@redhat.com>
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from distutils.version import StrictVersion
try:
    import shade
    HAS_SHADE = True
except ImportError:
    HAS_SHADE = False

DOCUMENTATION = '''
---
module: os_stack_get
short_description: Get Heat Stack
extends_documentation_fragment: openstack
version_added: "2.2"
author: "Tristan Cacqueray (tristanC)
description:
   - Get stack information
options:
    name:
      description:
        - Name of the stack that should be created
      required: true
requirements:
    - "python >= 2.6"
    - "shade"
'''
EXAMPLES = '''
---
- name: get stack
  ignore_errors: True
  register: stack_create
  os_stack_get:
    name: "{{ stack_name }}"
'''

RETURN = '''
id:
    description: Stack ID.
    type: string
    sample: "97a3f543-8136-4570-920e-fd7605c989d6"

stack: {}
'''


def main():
    argument_spec = openstack_full_argument_spec(  # noqa
        name=dict(required=True),
    )

    module_kwargs = openstack_module_kwargs()  # noqa
    module = AnsibleModule(argument_spec,  # noqa
                           supports_check_mode=True,
                           **module_kwargs)

    # stack API introduced in 1.8.0
    if not HAS_SHADE or \
       (StrictVersion(shade.__version__) < StrictVersion('1.8.0')):
        module.fail_json(
            msg='shade 1.8.0 or higher is required for this module')

    name = module.params['name']
    try:
        cloud = shade.openstack_cloud(**module.params)
        stack = cloud.get_stack(name)
        module.exit_json(changed=False, stack=stack, id=stack.id)
    except shade.OpenStackCloudException as e:
        module.fail_json(msg=str(e))

from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.openstack import *  # noqa
if __name__ == '__main__':
    main()
