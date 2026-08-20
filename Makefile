# pam_ldapdb.so Makefile
#
DESTDIR ?=

# Where libpam looks for modules. Distributions disagree, therefore we probe
# for a directory that actually exists instead. Packagers can override: make
# PAMDIR=/some/where install
MULTIARCH := $(shell $(CXX) -print-multiarch 2>/dev/null)
PAMDIRS   := $(if $(MULTIARCH),/lib/$(MULTIARCH)/security /usr/lib/$(MULTIARCH)/security)
PAMDIRS   += /lib64/security /usr/lib64/security /lib/security /usr/lib/security
PAMDIR    ?= $(firstword $(wildcard $(PAMDIRS)) /lib/security)

INSTALL     := install
INSTALL_DIR := $(INSTALL) -m 755 -d
INSTALL_PROGRAM := $(INSTALL) -m 755
INSTALL_LIBRARY := $(INSTALL) -m 644
RM      := rm -rf

CXX ?= g++
CXXFLAGS ?= -O2

REQUIRED_CXXFLAGS := -std=c++11 -Wall -Wextra -fstack-protector-strong

ifeq (,$(findstring _FORTIFY_SOURCE,$(CXXFLAGS)))
REQUIRED_CXXFLAGS += -D_FORTIFY_SOURCE=2
endif

REQUIRED_LDFLAGS := -Wl,-z,relro -Wl,-z,now

ALL_CXXFLAGS = $(REQUIRED_CXXFLAGS) $(CXXFLAGS)
ALL_LDFLAGS  = $(REQUIRED_LDFLAGS) $(LDFLAGS)
ALL_LDLIBS   = -lldap $(LDLIBS)

.PHONY: all library install clean

all: library

library: pam_ldapdb.so

pam_ldapdb.so: pam_ldapdb.o
	$(CXX) $(ALL_CXXFLAGS) $(ALL_LDFLAGS) -shared -o $@ $^ $(ALL_LDLIBS)

pam_ldapdb.o: pam_ldapdb.cpp
	$(CXX) $(ALL_CXXFLAGS) -fPIC -c -o $@ $<

install: pam_ldapdb.so
	$(INSTALL_DIR) $(DESTDIR)$(PAMDIR)
	$(INSTALL_LIBRARY) pam_ldapdb.so $(DESTDIR)$(PAMDIR)

clean:
	$(RM) *.o pam_ldapdb.so
