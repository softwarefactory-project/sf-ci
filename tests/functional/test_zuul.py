# Copyright (C) 2022 Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import config

from utils import Base, get_zuul_client


class TestZuulIntegration(Base):
    def _test_admin_is_admin(self, tenant):
        """Test that the admin account is admin on a tenant"""
        zc = get_zuul_client('admin', config.USERS['admin']['password'])
        authorizations = zc.authorizations(tenant)
        authorizations.raise_for_status()
        authz = authorizations.json()
        self.assertTrue(authz.get('zuul', False).
                        get('admin', False), authorizations)

    def test_admin_is_admin_on_local_tenant(self):
        """Test that the admin account is admin on default tenant"""
        self._test_admin_is_admin('local')
