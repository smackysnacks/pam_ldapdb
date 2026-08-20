#include <map>
#include <string>
#include <stdexcept>
#include <utility>
#include <cstring>
#include <syslog.h>
#include <pwd.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <ldap.h>

typedef std::map<std::string, std::string> ArgMap;

/* Seconds to wait on the directory before giving up. Without a bound the bind
 * blocks on the kernel TCP timeout. Overridable with timeout=<seconds>. */
#define LDAPDB_TIMEOUT_DEFAULT 10
#define LDAPDB_TIMEOUT_MAX     3600

/* Largest value uid_t can hold, as an unsigned long, for range-checking before
 * the narrowing cast. */
#define LDAPDB_UID_MAX ((unsigned long) (uid_t) -1)

static int ldap_to_pam_rc(int ldap_rc)
{
    switch (ldap_rc) {
    case LDAP_SUCCESS:
        return PAM_SUCCESS;
    case LDAP_UNAVAILABLE:
    case LDAP_TIMELIMIT_EXCEEDED:
    case LDAP_OPERATIONS_ERROR:
    case LDAP_BUSY:
    case LDAP_LOOP_DETECT:
    case LDAP_SERVER_DOWN:
    case LDAP_TIMEOUT:
    case LDAP_CONNECT_ERROR:
    case LDAP_NO_RESULTS_RETURNED:
    case LDAP_PROTOCOL_ERROR:
    case LDAP_AUTH_METHOD_NOT_SUPPORTED:
    case LDAP_STRONG_AUTH_REQUIRED:
    case LDAP_CONFIDENTIALITY_REQUIRED:
    case LDAP_INAPPROPRIATE_AUTH:
        return PAM_AUTHINFO_UNAVAIL;
    default:
        return PAM_AUTH_ERR;
    }
}

static int verify(const char* host,
                  const char* binddn,
                  const char* pw,
                  int timeout_sec)
{
    LDAP* ld;
    int ldap_rc, pam_rc;
    int version = LDAP_VERSION3;
    struct timeval tv;
    struct berval cred;

    ldap_rc = ldap_initialize(&ld, host);
    pam_rc = ldap_to_pam_rc(ldap_rc);
    if (pam_rc != PAM_SUCCESS)
        return pam_rc;

    ldap_rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (ldap_rc != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ld, NULL, NULL);
        return PAM_SERVICE_ERR;
    }

    /* This module performs exactly one bind and no searches, so it has no use
     * for referrals. libldap will not replay the password to a referred-to host
     * without ldap_set_rebind_proc(), which we never install, but that is a
     * guarantee worth not depending on in an authentication path. */
    if (ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)
            != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ld, NULL, NULL);
        return PAM_SERVICE_ERR;
    }

    /* NETWORK_TIMEOUT bounds the connect; TIMEOUT bounds the wait for the bind
     * response. */
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    if (ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv) != LDAP_OPT_SUCCESS ||
        ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv) != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ld, NULL, NULL);
        return PAM_SERVICE_ERR;
    }

    cred.bv_val = const_cast<char*>(pw);
    cred.bv_len = std::strlen(pw);
    ldap_rc = ldap_sasl_bind_s(ld, binddn, LDAP_SASL_SIMPLE, &cred,
                               NULL, NULL, NULL);

    ldap_unbind_ext_s(ld, NULL, NULL);

    return ldap_to_pam_rc(ldap_rc);
}


/* Accept a non-empty run of decimal digits and nothing else, and only a result
 * that fits the caller's ceiling. */
static bool parse_bounded_ulong(const std::string& in,
                                unsigned long max,
                                unsigned long& out)
{
    if (in.empty() || in.find_first_not_of("0123456789") != std::string::npos)
        return false;

    try {
        unsigned long value = std::stoul(in);
        if (value > max)
            return false;
        out = value;
    } catch (const std::exception&) {
        return false;
    }

    return true;
}


static ArgMap get_args(int argc,
                       const char** argv)
{
    ArgMap arguments;

    for (int i = 0; i < argc; i++) {
        std::string arg(argv[i]);
        std::string::size_type pos = arg.find("=");
        if (pos != std::string::npos) {
            std::string key = arg.substr(0, pos);
            std::string value = "";

            if (arg.length() > pos+1) {
                value = arg.substr(pos+1);
            }

            arguments.insert(std::make_pair(key, value));
        }
    }

    return arguments;
}


static void replace_all(std::string& s,
                        const std::string& search_s,
                        const std::string& replace_s)
{
    if (search_s.empty())
        return;

    std::string::size_type last_pos = 0;
    while ((last_pos = s.find(search_s, last_pos)) != std::string::npos) {
        s.replace(last_pos, search_s.length(), replace_s);
        last_pos += replace_s.length();
    }
}


/* The username is spliced into the binddn template, so a name carrying DN
 * metacharacters rewrites the structure of the distinguished name rather than
 * just its value: "bob,dc=evil" turns uid=%s,dc=x into uid=bob,dc=evil,dc=x,
 * and "bob+uid=root" builds a multi-valued RDN. Either controls which entry the
 * password is checked against.
 *
 * Reject rather than escape.
 *
 * Permitted: ASCII alphanumerics, "._-@$%", and any byte >= 0x80. Every RFC
 * 4514 special is ASCII, and UTF-8 continuation bytes are all >= 0x80, so
 * admitting the high range keeps non-ASCII usernames working without admitting
 * a metacharacter. This also excludes leading/trailing space, a leading '#',
 * and every control character, all of which are significant in a DN.
 *
 * '%' is deliberately allowed: it is not special in a DN, and here the username
 * is only ever the replacement text, never rescanned as a template. */
static bool username_is_dn_safe(const char* user)
{
    if (*user == '\0')
        return false;

    for (const unsigned char* p = (const unsigned char*) user; *p; p++) {
        if (*p >= 0x80)
            continue;
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9'))
            continue;
        if (*p == '.' || *p == '_' || *p == '-' ||
            *p == '@' || *p == '$' || *p == '%')
            continue;
        return false;
    }

    return true;
}


static int authenticate_impl(pam_handle_t* pamh,
                             int argc,
                             const char** argv)
{
    const char* user;
    const char* pass;
    uid_t minimum_uid = 0;
    uid_t maximum_uid = (uid_t) - 1;
    int timeout_sec = LDAPDB_TIMEOUT_DEFAULT;
    struct passwd *pwd;
    int ret;
    ArgMap arguments = get_args(argc, argv);

    ret = pam_get_user(pamh, &user, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    ret = pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    // ensure uri and binddn PAM parameters were specified
    if (arguments.find("uri") == arguments.end() ||
        arguments.find("binddn") == arguments.end()) {
        pam_syslog(pamh, LOG_NOTICE, "unable to find URI and/or BINDDN");
        return PAM_AUTH_ERR;
    }

    // get passwd entry for desired user. This is required for UID checking.
    pwd = getpwnam(user);
    if (!pwd) {
        pam_syslog(pamh, LOG_NOTICE, "unable to get uid for user %s", user);
        return PAM_AUTH_ERR;
    }

    // parse minimum_uid if given
    if (arguments.find("minimum_uid") != arguments.end()) {
        unsigned long value;
        if (!parse_bounded_ulong(arguments["minimum_uid"], LDAPDB_UID_MAX, value)) {
            pam_syslog(pamh, LOG_ERR, "minimum_uid=<%s> is not a valid uid "
                       "(expected 0-%lu)", arguments["minimum_uid"].c_str(),
                       LDAPDB_UID_MAX);
            return PAM_SERVICE_ERR;
        }
        minimum_uid = (uid_t) value;
    }

    // parse maximum_uid if given
    if (arguments.find("maximum_uid") != arguments.end()) {
        unsigned long value;
        if (!parse_bounded_ulong(arguments["maximum_uid"], LDAPDB_UID_MAX, value)) {
            pam_syslog(pamh, LOG_ERR, "maximum_uid=<%s> is not a valid uid "
                       "(expected 0-%lu)", arguments["maximum_uid"].c_str(),
                       LDAPDB_UID_MAX);
            return PAM_SERVICE_ERR;
        }
        maximum_uid = (uid_t) value;
    }

    // parse timeout if given
    if (arguments.find("timeout") != arguments.end()) {
        unsigned long value;
        if (!parse_bounded_ulong(arguments["timeout"], LDAPDB_TIMEOUT_MAX, value) || value < 1) {
            pam_syslog(pamh, LOG_ERR, "timeout=<%s> is not a valid duration (expected 1-%d seconds)",
                       arguments["timeout"].c_str(), LDAPDB_TIMEOUT_MAX);
            return PAM_SERVICE_ERR;
        }
        timeout_sec = (int) value;
    }

    // validate uid against min value
    if (minimum_uid > pwd->pw_uid || maximum_uid < pwd->pw_uid) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "uid out of range (%u <= %u <= %u)",
                   minimum_uid, pwd->pw_uid, maximum_uid);
        return PAM_AUTH_ERR;
    }

    // An empty credential is an *unauthenticated* bind, which a directory will
    // happily accept as anonymous and report as success, so it has to be caught
    // here rather than left to the server.
    if (std::strlen(pass) == 0) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "empty password for user %s", user);
        return PAM_AUTH_ERR;
    }

    // the username is about to be spliced into the DN template, so make sure it
    // cannot rewrite the DN's structure
    if (!username_is_dn_safe(user)) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: username "
                   "contains characters not permitted in a bind DN");
        return PAM_AUTH_ERR;
    }

    // parse & prepare binddn
    std::string binddn = arguments["binddn"];
    replace_all(binddn, "%s", user);

    // check against ldap database
    ret = verify(arguments["uri"].c_str(), binddn.c_str(), pass, timeout_sec);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "user=<%s> uri=<%s> binddn=<%s>",
                   user, arguments["uri"].c_str(), binddn.c_str());
    }
    return ret;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh,
                                   int /* flags */,
                                   int argc,
                                   const char** argv)
{
    /* libpam calls this from C. Letting an exception unwind out of here is
     * undefined behaviour and in practice reaches std::terminate, killing
     * whatever was authenticating -- sshd, the display manager, a screen
     * locker, etc. */
    try {
        return authenticate_impl(pamh, argc, argv);
    } catch (const std::exception &ex) {
        pam_syslog(pamh, LOG_CRIT, "internal error: %s", ex.what());
        return PAM_SERVICE_ERR;
    } catch (...) {
        pam_syslog(pamh, LOG_CRIT, "internal error: unknown exception");
        return PAM_SERVICE_ERR;
    }
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t* /* pamh */,
                              int /* flags */,
                              int /* argc */,
                              const char** /* argv */)
{
    return PAM_SUCCESS;
}
