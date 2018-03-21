#include <map>
#include <string>
#include <utility>
#include <syslog.h>
#include <pwd.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

typedef std::map<std::string, std::string> ArgMap;

static int ldap_to_pam_rc(int ldap_rc)
{
    switch (ldap_rc) {
    case LDAP_SUCCESS:
        /* everything was fine */
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
        /* cannot access LDAP correctly */
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* something else went wrong */
    return PAM_AUTH_ERR;
}

static int verify(const char* host,
                  const char* binddn,
                  const char* pw)
{
    LDAP* ld;
    int ldap_rc, pam_rc;

    ldap_rc = ldap_initialize(&ld, host);
    pam_rc = ldap_to_pam_rc(ldap_rc);
    if (pam_rc != PAM_SUCCESS)
        return pam_rc;

    ldap_rc = ldap_simple_bind_s(ld, binddn, pw);
    return ldap_to_pam_rc(ldap_rc);
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
    std::string::size_type last_pos = 0;
    while ((last_pos = s.find(search_s, last_pos)) != std::string::npos) {
        s.replace(last_pos, search_s.length(), replace_s);
    }
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh,
                                   int /* flags */,
                                   int argc,
                                   const char** argv)
{
    const char* user;
    const char* pass;
    uid_t minimum_uid = 0;
    uid_t maximum_uid = (uid_t) - 1;
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
        try {
            minimum_uid = (uid_t) std::stoul(arguments["minimum_uid"]);
        } catch (const std::invalid_argument &ex) {
            pam_syslog(pamh, LOG_ERR, "the given minimum_uid is invalid!");
            return PAM_AUTH_ERR;
        } catch (const std::out_of_range &ex) {
            pam_syslog(pamh, LOG_ERR, "the given minimum_uid is out of range!");
            return PAM_AUTH_ERR;
        }
    }

    // parse maximum_uid if given
    if (arguments.find("maximum_uid") != arguments.end()) {
        try {
            maximum_uid = (uid_t) std::stoul(arguments["maximum_uid"]);
        } catch (const std::invalid_argument &ex) {
            pam_syslog(pamh, LOG_ERR, "the given maximum_uid is invalid!");
            return PAM_AUTH_ERR;
        } catch (const std::out_of_range &ex) {
            pam_syslog(pamh, LOG_ERR, "the given maximum_uid is out of range!");
            return PAM_AUTH_ERR;
        }
    }

    // validate uid against min value
    if (minimum_uid > pwd->pw_uid || maximum_uid < pwd->pw_uid) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "uid out of range (%u <= %u <= %u)",
                   minimum_uid, pwd->pw_uid, maximum_uid);
        return PAM_AUTH_ERR;
    }

    // ldap_simple_bind_s accepts empty passwords for all users, therefore we
    // catch and deny them here...
    if (strlen(pass) == 0) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "empty password for user %s", user);
        return PAM_AUTH_ERR;
    }

    // parse & prepare binddn
    std::string binddn = arguments["binddn"];
    replace_all(binddn, "%s", user);

    // check against ldap database
    ret = verify(arguments["uri"].c_str(), binddn.c_str(), pass);
    if (ret != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "ldap authentication failure: "
                   "user=<%s> uri=<%s> binddn=<%s>",
                   user, arguments["uri"].c_str(), binddn.c_str());
    }
    return ret;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t* /* pamh */,
                              int /* flags */,
                              int /* argc */,
                              const char** /* argv */)
{
    return PAM_SUCCESS;
}
