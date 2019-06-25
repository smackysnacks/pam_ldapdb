[![Build Status](https://travis-ci.org/rmbreak/pam_ldapdb.svg?branch=master)](https://travis-ci.org/rmbreak/pam_ldapdb)

# PAM LDAPDB
Traditionally, before binding against an LDAP server with some user
credentials, you bind with a set of searching credentials so that you can query
the database for the distinguished name of a user's account. This PAM module
allows you to skip the searching step entirely, which is useful in cases where
you don't possess the necessary search credentials, but you do know the form of
a user's DN ahead of time.

## Building
With GCC and make installed, retrieve the development dependencies.

    CentOS 6 and 7
    # yum install pam-devel
    # yum install openldap-devel

    Debian 9
    $ sudo apt-get install libpam0g-dev libldap2-dev

Then run `make`

## Installing
`make install`

## Configuring
pam_ldapdb takes two arguments, `uri` and `binddn`. The `uri` parameter should
point to your LDAP server and includes the schema (e.g.
`uri=ldaps://my.ldap.server`). The `binddn` parameter is a template string that
contains one or more instances of `%s` that are to be replaced by the
connecting user. For example, if given `binddn=uid=%s,dc=my,dc=ldap,dc=server`
and the user `bob` is connecting then the new string will become
`uid=bob,dc=my,dc=ldap,dc=server`.

Modify `/etc/pam.d/*` to match your setup:

    auth sufficient pam_ldapdb.so uri=ldap://example.com binddn=uid=%s,dc=example,dc=com

## Optional Parameters

* `minimum_uid <uid>` ... If specified, a user must have a POSIX user ID of at least uid in order for logon authorization to succeed.
* `maximum_uid <uid>` ... If specified, a user must have a POSIX user ID of at most uid in order for logon authorization to succeed.

### Using pam_ldapdb with pam_ccreds
To enable offline LDAP authentication with pam_ldapdb the [pam_ccreds (cached
credentials) module](https://github.com/PADL/pam_ccreds) can be used. Therefore
make sure the desired user is available locally with a locked password (use:
`passwd -dl <username>`). Then configure pam "auth" to something similar like
the following example:

	auth    sufficient      pam_unix.so     nullok_secure
	auth    [success=3 default=2 authinfo_unavail=ignore]      pam_ldapdb.so ldap://example.com binddn=uid=%s,dc=example,dc=com
	auth    [success=2 default=ignore]                         pam_ccreds.so action=validate use_first_pass
	auth    [default=ignore]                                   pam_ccreds.so action=update
	auth    requisite       pam_deny.so
	auth    required        pam_permit.so
	auth    optional        pam_ccreds.so action=store

For more information on how PAM configuration and the pam_ccreds module works
please take a look at the corresponding documentation.

## Troubleshooting
### SELinux
If your system is running SELinux, you may need to enable the following policies:

    # setsebool -P nis_enabled 1
    # setsebool -P authlogin_nsswitch_use_ldap 1
