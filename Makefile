# pam_ldapdb.so Makefile
#
ARCH := $(shell getconf LONG_BIT)
DESTDIR ?=
PAMDIR_32 := /lib/security
PAMDIR_64 := /lib64/security
PAMDIR ?= $(PAMDIR_$(ARCH))

INSTALL		:= install
INSTALL_DIR	:= $(INSTALL) -m 755 -d
INSTALL_PROGRAM	:= $(INSTALL) -m 755
INSTALL_LIBRARY	:= $(INSTALL) -m 644
RM		:= rm -rf

CXX ?= g++
CFLAGS ?= -O2

CFLAGS += -Wall -Wextra
LDFLAGS	+= -Wl,-z,relro

all: library

library: pam_ldapdb.o
	$(CXX) $(CFLAGS) -shared -fPIC -o pam_ldapdb.so pam_ldapdb.cpp -lldap $(LDFLAGS)

install:
	$(INSTALL_DIR) $(DESTDIR)$(PAMDIR)
	$(INSTALL_LIBRARY) pam_ldapdb.so $(DESTDIR)$(PAMDIR)

clean:
	$(RM) *.o pam_ldapdb.so
