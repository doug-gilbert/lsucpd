%define name    lsucpd
%define version 0.90
%define release 1

Summary: 	List USB-C Power Delivery ports and partners
Name: 		%{name}
Version: 	%{version}
Release: 	%{release}
License:	GPL
Group:		Utilities/System
Source0:	https://sg.danny.cz/scsi/%{name}-%{version}.tar.gz
Url:		https://sg.danny.cz/scsi/lsurl.html
BuildRoot:	%{_tmppath}/%{name}-%{version}-root/
Packager:	dgilbert at interlog dot com

%description
Uses information provided by the sysfs pseudo file system in the Linux
kernel 2.6 series, and later, to list SCSI devices (Logical
Units (e.g. disks)) plus NVMe namespaces (SSDs). It can list transport
identifiers (e.g. SAS address of a SAS disk), protection information
configuration and size for storage devices. Alternatively it can be used
to list SCSI hosts (e.g. HBAs) or NVMe controllers. By default one line
of information is output per device (or host).

Author:
--------
    Doug Gilbert <dgilbert at interlog dot com>

%prep

%setup -q

%build
./autogen.sh
%configure

%install
if [ "$RPM_BUILD_ROOT" != "/" ]; then
        rm -rf $RPM_BUILD_ROOT
fi

make install \
        DESTDIR=$RPM_BUILD_ROOT

%clean
if [ "$RPM_BUILD_ROOT" != "/" ]; then
        rm -rf $RPM_BUILD_ROOT
fi

%files
%defattr(-,root,root)
%doc ChangeLog INSTALL README CREDITS AUTHORS COPYING
%attr(0755,root,root) %{_bindir}/*
%{_mandir}/man8/*


%changelog
* Tue Sep 12 2023 - dgilbert at interlog dot com
- initial version
  * lsucpd-0.90
