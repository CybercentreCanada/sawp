Name: sawp
Summary: Security Aware Wire Protocol parsing library (SAWP) FFI package
Version: %{version}
Release: 1
License: Copyright 2020 Crown Copyright, Government of Canada (Canadian Centre for Cyber Security / Communications Security Establishment)
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%package devel
Summary: Security Aware Wire Protocol parsing library (SAWP) FFI package headers and libraries
Requires: %{name} = %{version}-%{release}
Requires: pkgconfig

%description devel
%{summary}

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/libsawp*.so.*

%files devel
%{_libdir}/libsawp*.so
%{_includedir}/sawp/*.h