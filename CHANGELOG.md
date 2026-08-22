# Changelog

All notable changes to pam_ldapdb are documented here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.0.0] - 2026-08-22

### Security

- Reject usernames containing DN metacharacters to prevent changes to the
  generated `binddn`. Allowed characters are alphanumerics, `. _ - @ $ %`,
  and non-ASCII bytes. Invalid names return `PAM_AUTH_ERR` and are logged.
  ([#14])
- Disable LDAP referral chasing to prevent credentials from being sent to
  referred hosts. ([#13])

### Added

- Add `timeout=<seconds>` for LDAP connection and bind-response timeouts.
  Valid values are 1–3600; the default is 10 seconds. ([#13])
- Log unknown, duplicate, and malformed module arguments. The first duplicate
  value wins. PAM-managed arguments pass through without warnings. ([#14])
- Add `.clang-format` and reformat the source.

### Changed

- Use LDAPv3 explicitly, preventing LDAPv2 defaults or configuration-based
  downgrades. ([#13])
- Return `PAM_AUTHINFO_UNAVAIL` for directory configuration and protocol
  errors. Invalid credentials still return `PAM_AUTH_ERR`. ([#13])
- Replace deprecated `ldap_simple_bind_s` with `ldap_sasl_bind_s` using a
  `NULL` mechanism. Wire behavior is unchanged. ([#13])
- Require non-empty `uri` and `binddn` arguments, with at least one `%s`
  placeholder in `binddn`. ([#14])
- Use `CXXFLAGS` when compiling C++ and add hardening flags. ([#12])
- Detect the PAM installation directory, preferring multiarch paths. ([#12])
- Make `library` a phony alias for `pam_ldapdb.so`, and make `install` depend
  on the built module. ([#12])

### Fixed

- Release the LDAP handle after every authentication attempt, preventing
  connection and file-descriptor leaks in long-running processes. ([#13])
- Range-check `minimum_uid` and `maximum_uid` instead of silently truncating
  oversized values. ([#14])
- Prevent `replace_all()` from looping indefinitely when replacements contain
  the search string. ([#14])
- Catch exceptions before they cross the PAM C interface. Unexpected errors
  now return `PAM_SERVICE_ERR`. ([#14])
- Include `<cstring>` explicitly for `strlen`. ([#13])
- Add the missing `uri=` prefix to the README's pam_ccreds example. ([#14])

### Removed

- Remove Travis CI configuration and its build-status badge. ([#12])

## [1.3.1] - 2019-12-23

### Fixed

- Include `<stdexcept>` for `std::invalid_argument`.

### Removed

- Remove the bitbake recipe from the README.

## [1.3] - 2018-03-26

### Security

- Reject empty passwords, which LDAP otherwise treats as successful
  unauthenticated binds. Such attempts return `PAM_AUTH_ERR` and are logged.

### Added

- Add `minimum_uid=<uid>` and `maximum_uid=<uid>` authorization limits.
- Add pam_unix.so-style logging for authentication failures.
- Add Debian dependency installation instructions to the README.

### Fixed

- Preserve PAM error codes returned by `pam_get_user()` and
  `pam_get_authtok()`.
- Fix unused-parameter warnings.
- Pass the configured C++ standard to the compiler correctly.

## [1.2] - 2017-05-03

### Added

- Add LDAP-to-PAM error translation for pam_ldap and pam_ccreds compatibility.
  Unreachable-directory errors return `PAM_AUTHINFO_UNAVAIL`; other failures
  return `PAM_AUTH_ERR`.
- Add Makefile support for cross-compilation and architecture-specific
  installation directories.
- Add pam_ccreds cached-credential instructions to the README.
- Add a bitbake recipe to the README.

## [1.1] - 2015-09-10

### Fixed

- Replace every `%s` occurrence in `binddn`, not only the first.

### Added

- Add Travis CI integration and a build badge.

### Changed

- Use the `CXX` environment variable instead of `CC`.

## [1.0] - 2015-07-16

### Added

- Initial release of a PAM module that authenticates users by binding to LDAP
  with a DN generated from `uri`, `binddn`, and the username.

[#12]: https://github.com/smackysnacks/pam_ldapdb/pull/12
[#13]: https://github.com/smackysnacks/pam_ldapdb/pull/13
[#14]: https://github.com/smackysnacks/pam_ldapdb/pull/14

[unreleased]: https://github.com/smackysnacks/pam_ldapdb/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/smackysnacks/pam_ldapdb/compare/v1.3.1...v2.0.0
[1.3.1]: https://github.com/smackysnacks/pam_ldapdb/compare/v1.3...v1.3.1
[1.3]: https://github.com/smackysnacks/pam_ldapdb/compare/v1.2...v1.3
[1.2]: https://github.com/smackysnacks/pam_ldapdb/compare/v1.1...v1.2
[1.1]: https://github.com/smackysnacks/pam_ldapdb/compare/v1.0...v1.1
[1.0]: https://github.com/smackysnacks/pam_ldapdb/releases/tag/v1.0
