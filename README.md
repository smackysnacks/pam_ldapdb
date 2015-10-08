[![Build Status](https://travis-ci.org/rmbreak/pam_ldapdb.svg?branch=master)](https://travis-ci.org/rmbreak/pam_ldapdb)

# PAM LDAPDB
Traditionally, before binding against an LDAP server with some user
credentials, you bind with a set of searching credentials so that you can query
the database for the distinguished name of a user's account. This PAM module
allows you to skip the searching step entirely, which is useful in cases where
you don't possess the necessary search credentials, but you do know the form of
a user's DN ahead of time.

## Building
With GCC installed, retrieve the development dependencies.

    CentOS 6 and 7
    # yum install pam-devel
    # yum install openldap-devel

Then run `make`

## Installing
Move the compiled `pam_ldapdb.so` file to `/usr/lib64/security/` if you're
running a 64-bit system, otherwise move it to `/usr/lib/security/`.

## Configuring
pam_ldapdb takes two arguments, `uri` and `binddn`. The `uri` parameter should
point to your LDAP server and includes the schema (e.g.
`uri=ldaps://my.ldap.server`). The `binddn` parameter is a template string that
contains one or more instances of `%s` that are to be replaced by the
connecting user. For example, if given `binddn=uid=%s,dc=my,dc=ldap,dc=server`,
and the user `bob` is connecting then the PAM module will replace the binddn
with `uid=bob,dc=my,dc=ldap,dc=server`.

Modify `/etc/pam.d/*` to match your setup:

    auth sufficient pam_ldapdb.so uri=ldap://example.com binddn=uid=%s,dc=example,dc=com

## Troubleshooting
### SELinux
If your system is running SELinux, you will need to write the following policies:

    # setsebool -P nis_enabled 1
    # setsebool -P authlogin_nsswitch_use_ldap 1
