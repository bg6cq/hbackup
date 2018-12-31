Name:              hbackup
Version:           1.0
Release:           1%{?dist}

Summary:           A hashed file backup program
Group:             System Environment/Daemons
# BSD License (two clause)
# http://www.freebsd.org/copyright/freebsd-license.html
License:           GPLv3
URL:               https://github.com/bg6cq/hbackup
%if 0%{?rhel} == 5
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%endif

%description
A hashed file backup client


BuildRequires:     openssl-devel

Requires:    opensll

%prep

git clone https://github.com/bg6cq/hbackup

%build
cd hbackup
make

%install

install -p -D -m 0755 hbackup/hbackup \
    %{buildroot}%{_bindir}/hbackup

%files
%{_bindir}/hbackup

%changelog
* Mon Dec 31 2018 Zhang Huanjie <james@ustc.edu.cn> - 1.0
- first release

