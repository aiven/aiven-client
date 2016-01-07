%if %{?python3_sitelib:1}0
%global use_python3 1
%else
%global use_python3 0
%endif

Name:           aiven-client
Version:        %{major_version}
Release:        %{minor_version}%{?dist}
Url:            https://aiven.io/
Summary:        Aiven Client
License:        ASL 2.0
Source0:        rpm-src-aiven-client.tar
BuildArch:      noarch
%if %{use_python3}
Requires:       python3-requests
BuildRequires:  python3-devel, python3-flake8, python3-pylint, python3-pytest
%else
Requires:       python-requests
BuildRequires:  python-devel, python-flake8, pylint, pytest
%endif


%description
Aiven is a next-generation managed cloud services.  Its focus is in ease of
adoption, high fault resilience, customer's peace of mind and advanced
features at competetive price points.

aiven-client (`avn`) is the official command-line client for Aiven.


%prep
%setup -q -n aiven-client


%install
%{__mkdir_p} %{buildroot}%{_bindir}
%if %{use_python3}
sed -e 's,$PYTHON,python3,g' scripts/avn > %{buildroot}%{_bindir}/avn
%{__mkdir_p} %{buildroot}%{python3_sitelib}
cp -a aiven %{buildroot}%{python3_sitelib}/
%else
sed -e 's,$PYTHON,python,g' scripts/avn > %{buildroot}%{_bindir}/avn
%{__mkdir_p} %{buildroot}%{python_sitelib}
cp -a aiven %{buildroot}%{python_sitelib}/
%endif
chmod 755 %{buildroot}%{_bindir}/avn


%check
%if %{use_python3}
make test PYTHON=python3
%else
make test PYTHON=python2
%endif


%files
%defattr(-,root,root,-)
%doc LICENSE README.rst
%if %{use_python3}
%{python3_sitelib}/aiven
%else
%{python_sitelib}/aiven
%endif
%{_bindir}/avn


%changelog
* Wed Dec 23 2015 Aiven Support <support@aiven.io>
- Initial
