%global project aiven-client

Name:           %{project}
Version:        %{major_version}
Release:        %{minor_version}%{?dist}
Url:            https://github.com/aiven/%{project}
Source0:        rpm-src-aiven-client.tar
Summary:        Aiven Client
License:        ASL 2.0
BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3dist(wheel)
BuildRequires:  python3dist(hatchling)
BuildRequires:  python3dist(hatch-vcs)
BuildRequires:  python3dist(flake8)
BuildRequires:  python3dist(mypy)
BuildRequires:  python3dist(pytest)
BuildRequires:  python3dist(requests)
BuildRequires:  python3dist(pymysql)
BuildRequires:  python3dist(certifi)


%description
Aiven is a next-generation managed cloud services.  Its focus is in ease of
adoption, high fault resilience, customer's peace of mind and advanced
features at competitive price points.

aiven-client (`avn`) is the official command-line client for Aiven.

%prep
%autosetup -n %{name}

%generate_buildrequires
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}+%{minor_version}
%pyproject_buildrequires

%build
export SETUPTOOLS_SCM_PRETEND_VERSION=%{version}+%{minor_version}
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files aiven
%{__cp} aiven/client/py.typed %{buildroot}%{python3_sitelib}/aiven/client/py.typed

%check
%pyproject_check_import
%pytest

%files -n %{name} -f %{pyproject_files}
%license LICENSE
%doc README.rst
%{_bindir}/avn
%{python3_sitelib}/aiven/client/py.typed

%changelog
* Wed Dec 23 2015 Aiven Support <support@aiven.io>
- Initial
