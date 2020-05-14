#
# spec file for package osmo-remsim
#
# Copyright (c) 2018, Martin Hauke <mardnh@gmx.de>
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

%define sover 1
Name:           osmo-remsim
Version:        0.2.2.86
Release:        0
Summary:        Osmocom remote SIM software suite
License:        GPL-2.0-or-later
Group:          Productivity/Telephony/Servers
URL:            https://projects.osmocom.org/projects/osmo-remsim
Source:         %{name}-%{version}.tar.xz
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libcsv-devel
BuildRequires:  libtool
BuildRequires:  pkgconfig
BuildRequires:  systemd-rpm-macros
BuildRequires:  pkgconfig(libasn1c) >= 0.9.30
BuildRequires:  pkgconfig(libosmoabis)
BuildRequires:  pkgconfig(libosmocore) >= 0.11.0
BuildRequires:  pkgconfig(libosmogsm) >= 0.11.0
BuildRequires:  pkgconfig(libosmosim)
BuildRequires:  pkgconfig(libpcsclite)
BuildRequires:  pkgconfig(libulfius)
BuildRequires:  pkgconfig(libusb-1.0)
BuildRequires:  pkgconfig(libosmousb)
BuildRequires:  pkgconfig(libosmo-simtrace2)
%{?systemd_ordering}

%description
osmo-remsim is a suite of software programs enabling physical/geographic
separation of a cellular phone (or modem) on the one hand side and the
SIM/USIM/ISIM card on the other side.

Using osmo-remsim, you can operate an entire fleet of modems/phones, as
well as banks of SIM cards and dynamically establish or remove the
connections between modems/phones and cards.

So in technical terms, it behaves like a proxy for the ISO 7816 smart
card interface between the MS/UE and the UICC/SIM/USIM/ISIM.

While originally designed to be used in context of cellular networks,
there is nothing cellular specific in the system.  It can therefore also
be used with other systems that use contact based smart cards according
to ISO 7816.  Currently only the T=0 protocol with standard
(non-extended) APDUs is supported. Both T=1 and extended APDU support
can easily be added as a pure software update, should it be required at
some future point.

%package -n libosmo-rspro%{sover}
Summary:        Osmocom Remote SIM - Shared Library
License:        GPL-2.0-or-later
Group:          System/Libraries

%description -n libosmo-rspro%{sover}
libosmo-rsrpo is an utility library for encoding/decoding the ASN.1 BER
based RSPRO (Remote SIM Protocol) protocol used between the osmo-remsim
programs.

%package -n libosmo-rspro-devel
Summary:        Osmocom Remote SIM - Shared Library Development Haders
License:        GPL-2.0-or-later
Group:          Development/Libraries/C and C++
Requires:       libosmo-rspro%{sover} = %{version}

%description -n libosmo-rspro-devel
libosmo-rsrpo is an utility library for encoding/decoding the ASN.1 BER
based RSPRO (Remote SIM Protocol) protocol used between the osmo-remsim
programs.

This subpackage contains libraries and header files for developing
applications that want to make use of libosmo-rspro.

%package -n osmo-remsim-server
Summary:        Osmocom Remote SIM - Central Server
License:        GPL-2.0-or-later
Group:          Productivity/Telephony/Servers

%description -n osmo-remsim-server
The remsim-server is the central element of a osmo-remsim deployment,
it maintains a list of clients + bankds connected to it, as well as the
dynamic SIM card mappings between them.

%package -n osmo-remsim-bankd
Summary:        Osmocom Remote SIM - Bank Daemon
License:        GPL-2.0-or-later
Group:          Productivity/Telephony/Servers

%description -n osmo-remsim-bankd
The remsim-bankd is managing a bank of SIM card readers and their
respective cards. It establishes a control connection to remsim-server
and receives inbound connections from remsim-clients.

%package -n osmo-remsim-client-st2
Summary:        Osmocom Remote SIM - Client for SIMtrace2
License:        GPL-2.0-or-later
Group:          Productivity/Telephony/Servers

%description -n osmo-remsim-client-st2
Description: Osmocom Remote SIM - Client for SIMtrace2 cardem firmware
The remsim-client is managing a given phone/modem.  It attaches to the
'cardem' firmware of a SIMtrcace2 (or compatible, such as sysmoQMOD)
hardware and forwards the SIM card communication to a remsim-bankd,
under the control of remsim-server.

%package -n osmo-remsim-client-shell
Summary:        Osmocom Remote SIM - Interactive Client
License:        GPL-2.0-or-later
Group:          Productivity/Telephony/Servers

%description -n osmo-remsim-client-shell
The remsim-client-shell is for manually interacting with a remote SIM
card via remsim-bankd + remsim-server.  It's mostly a test/debug tool.

%package -n libifd-osmo-remsim-client0
Summary:        Osmocom Remote SIM Client - PC/SC driver
License:        GPL-2.0-or-later
Group:          Productivity/Telephony/Servers
Requires:       pcsc-lite

%description -n libifd-osmo-remsim-client0
This is an incarnation of osmo-remsim-client which can plug as ifd_handler
driver into pcscd.  This means you can use remote smart cards managed
by osmo-remsim-server via normal PC/SC applications.

%prep
%setup -q

%build
echo "%{version}" >.tarball-version
autoreconf -fi
%configure \
    --disable-static \
    --with-systemdsystemunitdir=%{_unitdir}
make V=1 %{?_smp_mflags}

%install
%make_install
find %{buildroot} -type f -name "*.la" -delete -print

%check
make %{?_smp_mflags} check || find . -name testsuite.log -exec cat {} +

%post   -n libosmo-rspro%{sover} -p /sbin/ldconfig
%postun -n libosmo-rspro%{sover} -p /sbin/ldconfig

%pre    -n osmo-remsim-bankd %service_add_pre     osmo-remsim-bankd.service
%post   -n osmo-remsim-bankd %service_add_post    osmo-remsim-bankd.service
%preun  -n osmo-remsim-bankd %service_del_preun   osmo-remsim-bankd.service
%postun -n osmo-remsim-bankd %service_del_postun  osmo-remsim-bankd.service

%pre    -n osmo-remsim-client-st2 %service_add_pre     osmo-remsim-client@.service
%post   -n osmo-remsim-client-st2 %service_add_post    osmo-remsim-client@.service
%preun  -n osmo-remsim-client-st2 %service_del_preun   osmo-remsim-client@.service
%postun -n osmo-remsim-client-st2 %service_del_postun  osmo-remsim-client@.service

%pre    -n osmo-remsim-server %service_add_pre    osmo-remsim-server.service
%post   -n osmo-remsim-server %service_add_post   osmo-remsim-server.service
%preun  -n osmo-remsim-server %service_del_preun  osmo-remsim-server.service
%postun -n osmo-remsim-server %service_del_postun osmo-remsim-server.service

%files -n libosmo-rspro%{sover}
%license COPYING
%doc README.md
%{_libdir}/libosmo-rspro.so.%{sover}*

%files -n libosmo-rspro-devel
%{_includedir}/osmocom
%dir %{_includedir}/osmocom/rspro
%{_includedir}/osmocom/rspro/rspro_client.h
%{_libdir}/libosmo-rspro.so
%{_libdir}/pkgconfig/libosmo-rspro.pc

%files -n osmo-remsim-server
%{_bindir}/osmo-remsim-server
%{_unitdir}/osmo-remsim-server.service

%files -n osmo-remsim-bankd
%{_bindir}/osmo-remsim-bankd
%{_unitdir}/osmo-remsim-bankd.service
%config %{_sysconfdir}/default/osmo-remsim-bankd

%files -n osmo-remsim-client-shell
%{_bindir}/osmo-remsim-client-shell

%files -n osmo-remsim-client-st2
%{_bindir}/osmo-remsim-client-st2
%{_unitdir}/osmo-remsim-client*
%config %{_sysconfdir}/default/osmo-remsim-client*

%files -n libifd-osmo-remsim-client0
%dir %{_libdir}/readers/
%dir %{_libdir}/readers/libifd-osmo-remsim-client.bundle
%dir %{_libdir}/readers/libifd-osmo-remsim-client.bundle/Contents
%{_libdir}/readers/libifd-osmo-remsim-client.bundle/Contents/PkgInfo
%dir %{_libdir}/readers/libifd-osmo-remsim-client.bundle/Contents/Linux
%{_libdir}/readers/libifd-osmo-remsim-client.bundle/Contents/Linux/libifd_remsim_client.so*
%config %{_sysconfdir}/reader.conf.d/osmo-remsim-client-reader_conf

%changelog
