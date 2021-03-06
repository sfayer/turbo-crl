# Remove python byte-code compile step
%global __os_install_post %(echo '%{__os_install_post}' | sed -e 's!/usr/lib[^[:space:]]*/brp-python-bytecompile[[:space:]].*$!!g')

Name:           turbo-crl
Version:        1.0.2
Release:        1%{?dist}
Summary:        A tool for downloading CRLs
Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/sfayer/turbo-crl
Source0:        https://raw.github.com/sfayer/turbo-crl/v1_0_2/turbo-crl.py
Source1:        https://raw.github.com/sfayer/turbo-crl/v1_0_2/turbo-crl.cron
Source2:        https://raw.github.com/sfayer/turbo-crl/v1_0_2/README
BuildArch:      noarch
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires:       openssl python

%description
Turbo-CRL is a tool for downloading CRL files for an OpenSSL 'hashdir' style
directory.

%prep
cp %{SOURCE2} README

%build

%install
rm -Rf %{buildroot}
# Install binary
mkdir -p %{buildroot}%{_bindir}
cp %{SOURCE0} %{buildroot}%{_bindir}/turbo-crl.py
chmod 755 %{buildroot}%{_bindir}/turbo-crl.py
# Install cron
mkdir -p %{buildroot}%{_sysconfdir}/cron.d
cp %{SOURCE1} %{buildroot}%{_sysconfdir}/cron.d
chmod 644 %{buildroot}%{_sysconfdir}/cron.d/turbo-crl.cron


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%{_bindir}/turbo-crl.py
%config(noreplace) %{_sysconfdir}/cron.d/turbo-crl.cron
%doc README

%changelog
* Sat Jul 06 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.2-1
- No changes yet!

* Tue Jul 02 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.1-1
- Fixed Ctrl+C handling.
- Write to a log file from cron by default.

* Tue Jul 02 2013 Simon Fayer <sf105@ic.ac.uk> - 1.0.0-1
- Initial version.

