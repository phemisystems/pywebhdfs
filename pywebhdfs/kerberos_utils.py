import kerberos
import krbV
import os.path
import subprocess

from collections import namedtuple
from datetime import datetime, timedelta


class KerberosContextManager(object):
    """
    This utility class authenticates the caller against Kerberos by sending a valid TGT from the
    default ccache. Upon success a service ticket is returned by the TGS and the appropriate
    NEGOTIATE header is constructed using the ticket.

    If there is no valid TGT present in the client's default ccache, or the TGT has expired, then
    it calls kinit to update the cache by passing in the client's credentials.
    """
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

    @staticmethod
    def _format_kerberos_credential_times(krbtgt_lookup):
        """
        Strip out and format the times retrieved from the ccache to be more user-friendly. All
        entries are stored in the cache as UNIX Epoch timestamps.

        :param krbtgt_lookup: the result obtained by looking up the TGT entry, including
                              credentials.
        :return: the times in a user-readable format.
        """
        credential_times = namedtuple('CredentialTime',
                                      'auth_time valid_starting expiry_date renew_until')

        return credential_times._make(datetime.fromtimestamp(t) for t in krbtgt_lookup[3])

    @staticmethod
    def _lookup_krbtgt_times(context, principal, ccache):
        """
        Retrieve the KRBTGT entry from the ccache, if present. We are interested in the times
        in order to determine if a cache refresh is necessary.

        :param context: the security context initiated with Kerberos.
        :param principal: the principal instance for the default principal.
        :param ccache: the default ccache instance.
        :return: the TGT times in a user-readable format.
        """
        ticket_granting_ticket = 'krbtgt/{0}@{0}'.format(principal.realm)

        tgt_principal = krbV.Principal(ticket_granting_ticket, context)

        # Credentials tuple elements:
        #   user principal (including instance qualifiers)
        #   tgt principal (i.e. 'krbtgt/<realm>@<realm>')
        #   keyblock: (enc_type, contents)
        #   times: (auth_time, valid_starting, expiry_date, renew_until)
        #   is key
        #   ticket flags
        #   addrlist (address list to search)
        #   ticket data
        #   second ticket data
        #   active directory list
        credentials = (principal, tgt_principal, (0, None), (0, 0, 0, 0),
                       None, None, None, None, None, None)
        result = ccache.get_credentials(credentials, krbV.KRB5_GC_CACHED, 0)

        return KerberosContextManager._format_kerberos_credential_times(result)

    @staticmethod
    def _are_credential_times_expired(credential_times):
        """
        Check the date to see if the TGT is about to expire, or has already expired.

        :param credential_times: the TGT times in a user-readable format.
        :return: boolean result indicating whether or not the ticket has expired.
        """
        current_date = datetime.now()
        time_remaining = credential_times.expiry_date - current_date
        if time_remaining < timedelta(minutes=5):
            return True

        return False

    def _is_kerberos_ccache_refresh_required(self):
        """
        Check if we need to get a new TGT and refresh the default ccache. If the ccache is empty,
        this function will indicate that a refresh is necessary.

        :return: boolean result indicating whether or not a new TGT must be requested.
        """
        krb_context = krbV.default_context()
        krb_ccache = krb_context.default_ccache()
        krb_principal = krbV.Principal(self.krb_conn_settings['principal'], krb_context)

        try:
            credential_times = self._lookup_krbtgt_times(krb_context,
                                                         krb_principal,
                                                         krb_ccache)

            return self._are_credential_times_expired(credential_times)
        except krbV.Krb5Error:
            return True

    def _build_kinit_cmd(self, aux_args=None):
        """
        Helper function to build the kinit command, adding any extra commandline arguments.

        :param aux_args:
        :return:
        """
        credentials = '{0}@{1}'.format(self.krb_conn_settings['principal'],
                                       self.krb_conn_settings['realm'])

        kinit_cmd = ['kinit', credentials]
        if aux_args:
            kinit_cmd.extend(aux_args)

        return kinit_cmd

    def refresh_kerberos_ccache(self, aux_args=None):
        """
        Refresh the Kerberos client's default ccache by calling kinit in a subprocess if the TGT
        in the cache has expired.

        :param aux_args: extra commandline arguments passed to kinit.
        :return: boolean result indicating success or failure, and a helpful message.
        """
        if self._is_kerberos_ccache_refresh_required():
            kinit_cmd = self._build_kinit_cmd(aux_args)
            try:
                if self.using_keytab:
                    keytab = self.krb_conn_settings['keytab_file']
                    kinit_cmd.extend(['-k', '-t', keytab])
                    kinit_cmd = subprocess.Popen(kinit_cmd,
                                                 stdin=subprocess.PIPE,
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)
                    kinit_cmd.wait()
                else:
                    kinit_cmd = subprocess.Popen(kinit_cmd,
                                                 stdin=subprocess.PIPE,
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)
                    kinit_cmd.stdin.write('{0}\n'.format(self.krb_conn_settings['passwd']))
                    kinit_cmd.wait()
            except subprocess.CalledProcessError as badcall:
                return False, badcall.output
            except OSError as oserr:
                return False, oserr.strerror

        return True, ""

    def acquire_kerberos_ticket(self):
        """
        Acquire a new Kerberos service ticket using the TGT in the client's default ccache. This
        ticket is used to communicate with the service directly and must be included in the header
        of the request.

        :return: header field to be included in the service request.
        """
        self.refresh_kerberos_ccache()

        krb_server = 'HTTP@{0}'.format(self.krb_conn_settings['server'])
        _, krb_context = kerberos.authGSSClientInit(service=krb_server,
                                                    principal=self.krb_conn_settings['principal'])

        kerberos.authGSSClientStep(krb_context, '')
        ticket = kerberos.authGSSClientResponse(krb_context)
        kerberos.authGSSClientClean(krb_context)

        return 'Negotiate {0}'.format(ticket)
