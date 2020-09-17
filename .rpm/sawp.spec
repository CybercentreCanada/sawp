Name: sawp
Summary: Security Aware Wire Protocol parsing library
Version: @@VERSION@@
Release: @@RELEASE@@%{?dist}
License: Copyright 2020 Crown Copyright, Government of Canada (Canadian Centre for Cyber Security / Communications Security Establishment)
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%prep
%setup

%install
# Do anything needed to make the buildroot
# directory look exactly like we want it to
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr