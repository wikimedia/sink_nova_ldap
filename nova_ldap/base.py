# Copyright 2015 Andrew Bogott for the Wikimedia Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
from oslo.config import cfg
from designate import exceptions
from designate.openstack.common import log as logging
from designate.central import rpcapi as central_rpcapi
from designate.context import DesignateContext
from designate.notification_handler.base import BaseAddressHandler
from designate.notification_handler.base import get_ip_data
from designate.plugin import ExtensionPlugin

import ldap
import ldap.modlist
import paramiko

LOG = logging.getLogger(__name__)
central_api = central_rpcapi.CentralAPI()


class BaseAddressLdapHandler(BaseAddressHandler):

    def _getLdapInfo(self, attr, conffile="/etc/ldap.conf"):
        try:
            f = open(conffile)
        except IOError:
            if conffile == "/etc/ldap.conf":
                # fallback to /etc/ldap/ldap.conf, which will likely
                # have less information
                f = open("/etc/ldap/ldap.conf")
        for line in f:
            if line.strip() == "":
                continue
            if line.split()[0].lower() == attr.lower():
                return line.split(None, 1)[1].strip()
                break

    def _initLdap(self):
        self.base = self._getLdapInfo("base")
        self.ldapHost = self._getLdapInfo("uri")
        self.sslType = self._getLdapInfo("ssl")

        self.binddn = cfg.CONF[self.name].get('ldapusername')
        self.bindpw = cfg.CONF[self.name].get('ldappassword')

    def _openLdap(self):
        self.ds = ldap.initialize(self.ldapHost)
        self.ds.protocol_version = ldap.VERSION3
        if self.sslType == "start_tls":
            self.ds.start_tls_s()

        try:
            self.ds.simple_bind_s(self.binddn, self.bindpw)
            return self.ds
        except ldap.CONSTRAINT_VIOLATION:
            LOG.debug("LDAP bind failure:  Too many failed attempts.\n")
        except ldap.INVALID_DN_SYNTAX:
            LOG.debug("LDAP bind failure:  The bind DN is incorrect... \n")
        except ldap.NO_SUCH_OBJECT:
            LOG.debug("LDAP bind failure:  Unable to locate the bind DN account.\n")
        except ldap.UNWILLING_TO_PERFORM, msg:
            LOG.debug("LDAP bind failure:  The LDAP server was unwilling to perform the action requested.\nError was: %s\n" % msg[0]["info"])
        except ldap.INVALID_CREDENTIALS:
            LOG.debug("LDAP bind failure:  Password incorrect.\n")

        return None

    def _closeLdap(self):
        self.ds.unbind()

    def _create(self, addresses, extra, managed=True,
                resource_type=None, resource_id=None):
        """
        Create a a record from addresses

        :param addresses: Address objects like
                          {'version': 4, 'ip': '10.0.0.1'}
        :param extra: Extra data to use when formatting the record
        :param managed: Is it a managed resource
        :param resource_type: The managed resource type
        :param resource_id: The managed resource ID
        """
        LOG.debug('Initializing ldap')
        self._initLdap()
        if not self._openLdap():
            return

        LOG.debug('Using DomainID: %s' % cfg.CONF[self.name].domain_id)
        domain = self.get_domain(cfg.CONF[self.name].domain_id)
        LOG.debug('Domain: %r' % domain)

        data = extra.copy()
        LOG.debug('Event data: %s' % data)
        data['domain'] = domain['name']

        # Just one ldap entry per host, please.
        addr = addresses[0]

        event_data = data.copy()
        event_data.update(get_ip_data(addr))
        dc = ("%(hostname)s.%(tenant_id)s.%(domain)s" % event_data).rstrip('.')
        dn = "dc=%s,ou=hosts,dc=wikimedia,dc=org" % dc

        hostEntry = {}
        hostEntry['objectClass'] = ['domainrelatedobject',
                                    'dnsdomain',
                                    'puppetclient',
                                    'domain',
                                    'dcobject',
                                    'top']
        hostEntry['l'] = 'eqiad'
        hostEntry['dc'] = dc
        hostEntry['aRecord'] = addr
        hostEntry['puppetClass'] = cfg.CONF[self.name].get(
            'puppetdefaultclasses')
        hostEntry['puppetVar'] = cfg.CONF[self.name].get(
            'puppetdefaultvars')
        hostEntry['associatedDomain'] = []
        hostEntry['puppetVar'].append('instanceproject=%s' %
                                      event_data['tenant_id'])
        hostEntry['puppetVar'].append('instancename=%s' %
                                      event_data['hostname'])

        for fmt in cfg.CONF[self.name].get('format'):
            hostEntry['associatedDomain'].append((fmt % event_data).rstrip('.'))

        if managed:
            LOG.debug('Creating ldap record')

            modlist = ldap.modlist.addModlist(hostEntry)
            self.ds.add_s(dn, modlist)

        self._closeLdap()

    def _delete(self, extra, managed=True, resource_id=None,
                resource_type='instance', criterion={}):
        """
        Handle a generic delete of a fixed ip within a domain

        :param criterion: Criterion to search and destroy records
        """
        LOG.debug('Initializing ldap')
        self._initLdap()
        if not self._openLdap():
            return

        LOG.debug('Delete using DomainID: %s' % cfg.CONF[self.name].domain_id)
        domain = self.get_domain(cfg.CONF[self.name].domain_id)
        LOG.debug('Domain: %r' % domain)

        data = extra.copy()
        LOG.debug('Event data: %s' % data)
        data['domain'] = domain['name']

        event_data = data.copy()

        dc = "%(hostname)s.%(tenant_id)s.%(domain)s" % event_data
        dn = "dc=%s,ou=hosts,dc=wikimedia,dc=org" % dc

        self.ds.delete_s(dn)

        self._closeLdap()

        # WMF-specific add-on:  Clean salt and puppet keys for deleted
        #  instance
        if (cfg.CONF[self.name].puppet_key_format and
                cfg.CONF[self.name].puppet_master_host):
            puppetkey = cfg.CONF[self.name].puppet_key_format % event_data
            LOG.debug('Cleaning puppet key %s' % puppetkey)
            _run_remote_command(cfg.CONF[self.name].puppet_master_host,
                                cfg.CONF[self.name].certmanager_user,
                                'sudo puppet cert clean %s' % puppetkey)

        if (cfg.CONF[self.name].salt_key_format and
                cfg.CONF[self.name].salt_master_host):
            saltkey = cfg.CONF[self.name].salt_key_format % event_data
            LOG.debug('Cleaning salt key %s' % saltkey)
            _run_remote_command(cfg.CONF[self.name].salt_master_host,
                                cfg.CONF[self.name].certmanager_user,
                                'sudo salt-key -y -d  %s' % saltkey)

    def _run_remote_command(server, username, command):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(server, username=username)
            except (paramiko.SSHException, socket.error):
                LOG.warning('Failed to connect to %s' % server)
                return
            stdin, stdout, stderr = ssh.exec_command(command)
            LOG.debug('remote call produced stdout %s' % stdout)
            LOG.debug('remote call produced stderr %s' % stderr)
            return stdout.readlines()
        except Exception:
            LOG.warning('Unable to connect to %s' % server)
            return
