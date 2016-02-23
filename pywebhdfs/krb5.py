import krbV

def testing_krb5():
    principal_name = "phemi/dev"
    realm_name = "DEV.PHEMI.COM"
    krb_server = "dev"
    keytab_file = "/home/ubuntu/agile/phemi.keytab"
    ccache_file = "/tmp/test-cache"

    context = krbV.default_context()
    principal = krbV.Principal(name=principal_name, context=context)
    keytab = krbV.Keytab(name=keytab_file, context=context)
    ccache = krbV.CCache(name=ccache_file, context=context, primary_principal=principal)

    try:
        cred_time = get_tgt_time(context, ccache, principal)
    except krbV.Krb5Error, err:
        # Credentials cache does not exist. In this case, initialize
        # credential cache is required.
        monitor_errors = (krbV.KRB5_FCC_NOFILE,
                          krbV.KRB5_CC_FORMAT,
                          krbV.KRB5_CC_NOTFOUND,)
        err_code = err.args[0]
        is_init_required = err_code in monitor_errors
        if is_init_required:
            print err
            print "True"
        else:
            # If error is unexpected, raise it to caller
            print "False"

def get_login():
    ''' Get current effective user name '''
    return pwd.getpwuid(os.getuid()).pw_name


def build_tgt_ticket(principal):
    return 'krbtgt/%(realm)s@%(realm)s' % {'realm': principal.realm}


def get_tgt_time(context, ccache, principal):
    ''' Get specified TGT's credential time.
    Arguments:
    - context, current context object.
    - ccache, the CCache object that is associated with context.
    - principal, the principal that is being used for getting ticket.
    '''
    tgt_princ = krbV.Principal(build_tgt_ticket(principal), context=context)
    creds = (principal, tgt_princ,
             (0, None), (0, 0, 0, 0), None, None, None, None,
             None, None)
    result = ccache.get_credentials(creds, krbV.KRB5_GC_CACHED, 0)
    time_conv = datetime.fromtimestamp
    return CredentialTime._make([time_conv(t) for t in result[3]])

testing_krb5()
