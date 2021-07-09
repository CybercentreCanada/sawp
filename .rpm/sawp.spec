Name: sawp
Summary: Security Aware Wire Protocol parsing library
Version: %{version}
Release: 1
License: Copyright 2020 Crown Copyright, Government of Canada (Canadian Centre for Cyber Security / Communications Security Establishment)
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

%post
for file in %{_libdir}/libsawp*.so*; do
    trimmed=$(echo $file | sed -rn --expression='s/(.*\.so)[.0-9A-Za-z-]+/\1/p')
    ln -sf $file $trimmed
done

/sbin/ldconfig

%preun
for file in %{_libdir}/libsawp*.so*; do
    trimmed=$(echo $file | sed -rn --expression='s/(.*\.so)[.0-9A-Za-z-]+/\1/p')
    rm -f $trimmed
done

%postun
rm -rf %{_includedir}/sawp
/sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/libsawp*.so*
%{_includedir}/sawp/*.h
