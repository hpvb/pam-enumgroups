%if 0%{?fedora} > 16 || 0%{?rhel} > 6
%global security_parent_dir /%{_libdir}
%else
%global security_parent_dir /%{_lib}
%endif

Summary: Simple PAM module to work around a problem with external groups that can't be resolved by member
Name: pam-enumgroups
Version: 1.0.0
Release: 2
License: GPL
Vendor: Hein-Pieter van Braam
Group: System Environment/Base
Source: %{name}-%{version}.tar.gz
Requires: pam

%description
The pam_enumgroups PAM module enumerates all groups using getgrent(3), it checks what groups have a member of the named user and adds them to the sessions' group vector using setgroups(2), . This is useful when group memberships are visible when querying a group directly but not when trying to resolve group membership of a user by querying on groupname. This can occur with NSS databases such as LDAP. It is generally better to not rely on this module but restructure the database or switch to sssd.

%prep
%setup -q

%build
%configure --with-libsecuritydir=/%{security_parent_dir}/security
make %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT INSTALL="install -p"
rm -f $RPM_BUILD_ROOT/%{security_parent_dir}/security/*.la
rm -f $RPM_BUILD_ROOT/%{security_parent_dir}/security/*.a

%files 
%defattr(-,root,root,-)
%{security_parent_dir}/security/*.so
%doc README
%{_mandir}/man8/*

