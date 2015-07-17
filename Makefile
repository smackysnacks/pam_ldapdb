CXX=g++

all: library

library: pam_ldapdb.o
	$(CXX) -shared -fPIC -o pam_ldapdb.so pam_ldapdb.cpp -lldap

clean:
	rm *.o pam_ldapdb.so
