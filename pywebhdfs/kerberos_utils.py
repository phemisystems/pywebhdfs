import kerberos
import krbV
import os.path
import subprocess

from collections import namedtuple
from datetime import datetime, timedelta


class KerberosContextManager(object):
    def __init__(self, krb_conn_settings, using_keytab=True):
        for param in ['principal', 'realm', 'server']:
            if param not in krb_conn_settings:
                raise ValueError('Missing parameter {0}'.format(param))

        if using_keytab:
            if 'keytab_file' not in krb_conn_settings:
                raise ValueError('Failed to specify path to keytab')
            keytab = krb_conn_settings['keytab_file']
            if not os.path.isfile(keytab):
                raise ValueError('Keytab does not exist')
        else:
            if 'passwd' not in krb_conn_settings:
                raise ValueError('Password is required if not using keytab')

        self.krb_conn_settings = krb_conn_settings
        self.using_keytab = using_keytab

    def _lookup_krbtgt_times(self, context, principal, ccache):
        credential_times = namedtuple('CredentialTime',
                                      'auth_time valid_starting expiry_date renew_until')

        ticket_granting_ticket = 'krbtgt/{0}@{0}'.format(principal.realm)
        tgt_principal = krbV.Principal(name=ticket_granting_ticket, context=context)
        credentials = (principal, tgt_principal, (0, None), (0, 0, 0, 0), None, None, None, None,
                       None, None)
        result = ccache.get_credentials(credentials, krbV.KRB5_GC_CACHED, 0)

        return credential_times._make(datetime.fromtimestamp(t) for t in result[3])

    def _build_kinit_cmd(self, aux_args):
        credentials = '{0}@{1}'.format(self.krb_conn_settings['principal'],
                                       self.krb_conn_settings['realm'])

        kinit_cmd = ['kinit', credentials]
        if aux_args:
            kinit_cmd.extend(aux_args)

        return kinit_cmd

    def refresh_kerberos_ccache(self, aux_args=None):
        refresh_required = False

        if self.using_keytab:
            krb_context = krbV.default_context()
            krb_ccache = krb_context.default_ccache()
            krb_principal = krbV.Principal(name=self.krb_conn_settings['principal'],
                                           context=krb_context)

            try:
                credential_times = self._lookup_krbtgt_times(context=krb_context,
                                                             principal=krb_principal,
                                                             ccache=krb_ccache)
                current_date = datetime.now()
                time_remaining = credential_times.expiry_date - current_date
                if time_remaining < timedelta(minutes=5):
                    refresh_required = True
            except krbV.Krb5Error:
                refresh_required = True

        if refresh_required:
            kinit_cmd = self._build_kinit_cmd(aux_args)

            try:
                if self.using_keytab:
                    keytab = self.krb_conn_settings['keytab']
                    kinit_cmd.extend(['-k', '-t', keytab])

                    kinit_cmd = subprocess.Popen(*kinit_cmd,
                                                 stdin=subprocess.PIPE,
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)
                    kinit_cmd.wait()
                else:
                    kinit_cmd = subprocess.Popen(*kinit_cmd,
                                                 stdin=subprocess.PIPE,
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)
                    kinit_cmd.stdin.write('{0}\n'.format(self.krb_conn_settings['passwd']))
                    kinit_cmd.wait()
            except subprocess.CalledProcessError as badcall:
                return False, badcall.output
            except OSError as oserr:
                return False, oserr.strerr

        return True, ""

    def acquire_kerberos_ticket(self):
        self.refresh_kerberos_ccache()

        krb_server = 'HTTP@{0}'.format(self.krb_conn_settings['server'])
        _, krb_context = kerberos.authGSSClientInit(service=krb_server,
                                                    principal=self.krb_conn_settings['principal'])

        kerberos.authGSSClientStep(krb_context, '')
        ticket = kerberos.authGSSClientResponse(krb_context)
        kerberos.authGSSClientClean(krb_context)

        return 'Negotiate {0}'.format(ticket)
