from kerberos_utils import KerberosContextManager
from webhdfs import PyWebHdfsClient

KERBEROS = dict(
    principal="phemi/dev",
    realm="DEV.PHEMI.COM",
    server="dev",
    keytab_file="/home/ubuntu/agile/phemi.keytab",
    ccache_file="/tmp/phemi_ccache"
)

kcm = KerberosContextManager(krb_conn_settings=KERBEROS)
print "___                                                                 ___"
print "___ TESTING: Access to HDFS in an environment secured with Kerberos ___"
print "___                                                                 ___"
print
print "    Kerberos server:\t\t{0}".format(kcm.krb_conn_settings['server'])
print "    Kerberos credentials:\tprincipal:\t{0},\n\t\t\t\trealm:\t\t{1}".format(kcm.krb_conn_settings['principal'],
                                                                                  kcm.krb_conn_settings['realm'])
print
if kcm.using_keytab:
    print "    Using keytab file located at:\n\t{0}".format(kcm.krb_conn_settings['keytab_file'])
print
print "___                                                                 ___"
print "___ HDFS: Testing queries against HDFS                              ___"
print "___                                                                 ___"
print

hdfs = PyWebHdfsClient(host='dev', port='50070', krb_instance=kcm)
#hdfs.create_file('user/hdfs/test-phemi', 'DATA ADDED!')
print hdfs.list_dir('user/hdfs')
print hdfs.read_file('user/hdfs/test-phemi')

