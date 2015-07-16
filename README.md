Include the following in your PAM configuration

    auth    sufficient    pam_ldapdb.so uri=ldap://example.com binddn=uid=%s,dc=example,dc=com

Tested on CentOS 6 and 7 x86_64
