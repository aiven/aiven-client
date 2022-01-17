Name:           aiven-client
Version:        %{major_version}
Release:        %{minor_version}%{?dist}
Url:            https://aiven.io/
Summary:        Aiven Client
License:        ASL 2.0
Source0:        rpm-src-aiven-client.tar
BuildArch:      noarch
Requires:       python3-requests
BuildRequires:  python3-devel, python3-flake8, python3-mypy, python3-pylint, python3-pytest


%description
Aiven is a next-generation managed cloud services.  Its focus is in ease of
adoption, high fault resilience, customer's peace of mind and advanced
features at competitive price points.

aiven-client (`avn`) is the official command-line client for Aiven.


%prep
%setup -q -n aiven-client


%install
%{__mkdir_p} %{buildroot}%{_bindir}
%{__mkdir_p} %{buildroot}%{python3_sitelib}
cp -a aiven %{buildroot}%{python3_sitelib}/
cp scripts/avn %{buildroot}%{_bindir}/avn
chmod 755 %{buildroot}%{_bindir}/avn


%check
make test


%files
%defattr(-,root,root,-)
%doc LICENSE README.rst
%{python3_sitelib}/aiven
%{_bindir}/avn


%changelog
* Wed Dec 23 2015 Aiven Support <support@aiven.io>
- Initial
