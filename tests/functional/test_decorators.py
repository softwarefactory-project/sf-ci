# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
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

from utils import Base
from utils import skipIfServiceMissing, skipIfServicePresent


class TestConditionalTesting(Base):
    """Functional tests validating the service decorators. If the tests
    are not skipped as expected, fail the tests.
    """
    @skipIfServiceMissing('SomeLameFantasyServiceThatDoesNotExist')
    def test_skip_if_service_missing(self):
        self.fail('Failure to detect that a service is missing')

    # assuming gerrit will always be there ...
    @skipIfServicePresent('gerrit')
    def test_skip_if_service_present(self):
        self.fail('Failure to detect that a service is present')
