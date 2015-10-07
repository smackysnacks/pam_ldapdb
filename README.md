[![Build Status](https://travis-ci.org/rmbreak/pam_ldapdb.svg?branch=master)](https://travis-ci.org/rmbreak/pam_ldapdb)

# PAM LDAPDB
Traditionally, before binding against an LDAP server with some user
credentials, you bind with a set of searching credentials so you can query the
database for the distinguished name of a user's account. This PAM module allows
you to skip the searching step entirely. This is useful in such a case where
you don't have a set of search credentials, but you know ahead of time what a
user's DN is.

## Building
With GCC installed, retrieve the development dependencies.

    CentOS 6 and 7
    # yum install pam-devel
    # yum install openldap-devel

Then run `make`

## Installing
Move the compiled `pam_ldapdb.so` file to `/usr/lib64/security/` if you're
running a 64 system, otherwise move it to `/usr/lib/security/`.

## Configure
Modify `/etc/pam.d/*` to fit your needs, such as the following:

    auth  sufficient  pam_ldapdb.so uri=ldap://example.com binddn=uid=%s,dc=example,dc=com

## Troubleshooting
### SELinux
If your system is running SELinux, you will need to write the following policies:

    # setsebool -P nis_enabled 1
    # setsebool -P authlogin_nsswitch_use_ldap 1
