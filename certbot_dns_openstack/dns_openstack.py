# -*- coding: utf-8 -*-

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
import logging

import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common

from openstack.config import loader
from openstack import connection

from acme import challenges
from certbot import achallenges
from certbot.display import util as display_util
from time import sleep
from typing import List


LOG = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for OpenStack

    This Authenticator uses the OpenStack v2 DNS API to fulfill a
    dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record.'
    ttl = 60

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=30)
        add('client_config', help='OpenStack Client Config file.')
        add('cloud', help='OpenStack to use.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a ' + \
               'dns-01 challenge using the OpenStack DNS API.'

    def _setup_credentials(self):
        config_file = self.conf('client_config') or ''
        config = loader.OpenStackConfig(
            config_files=loader.CONFIG_FILES + [config_file])
        self.cloud = connection.Connection(
            config=config.get_one(
                self.conf('cloud')
            )
        )

    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]: # pylint: disable=missing-function-docstring
        self._setup_credentials()

        self._attempt_cleanup = True

        responses = []
        for achall in achalls:
            domain = self.config.namespace.domains[0]
            validation_domain_name = achall.validation_domain_name(achall.domain)
            validation = achall.validation(achall.account_key)

            self._perform(domain, validation_domain_name, validation)
            responses.append(achall.response(achall.account_key))

        # DNS updates take time to propagate and checking to see if the update has occurred is not
        # reliable (the machine this code is running on might be able to see an update before
        # the ACME server). So: we sleep for a short amount of time we believe to be long enough.
        display_util.notify("Waiting %d seconds for DNS changes to propagate" %
                    self.conf('propagation-seconds'))
        sleep(self.conf('propagation-seconds'))

        return responses

    def _perform(self, domain, validation_name, validation):
        base_domain = '.'.join(domain.split('.')[1:])
        self.zone = self.cloud.get_zone(base_domain + '.')
        self.recordset = self.cloud.create_recordset(
            self.zone['id'], validation_name + '.', "TXT", [validation])

    def _cleanup(self, domain, validation_name, validation):
        self.cloud.delete_recordset(
            self.zone['id'], self.recordset['id'])
