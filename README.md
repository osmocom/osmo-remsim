osmo-remsim - Osmocom remote SIM software suite
===============================================

osmo-remsim is a suite of software programs enabling physical/geographic separation of a cellular phone (or
modem) on the one hand side and the SIM/USIM/ISIM card on the other side.

Using osmo-remsim, you can operate an entire fleet of modems/phones, as well as banks of SIM cards and
dynamically establish or remove the connections between modems/phones and cards.

So in technical terms, it behaves like a proxy for the ISO 7816 smart card interface between the MS/UE and the
UICC/SIM/USIM/ISIM.

While originally designed to be used in context of cellular networks, there is nothing cellular specific in
the system. It can therefore also be used with other systems that use contact based smart cards according to
ISO 7816. Currently only the T=0 protocol with standard (non-extended) APDUs is supported.

Homepage
--------
Please visit the [official homepage](https://osmocom.org/projects/osmo-remsim/wiki)
for usage instructions, manual and examples.


GIT Repository
--------------

You can clone from the official osmo-remsim.git repository using

        git clone https://gitea.osmocom.org/sim-card/osmo-remsim

There is a web interface at <https://gitea.osmocom.org/sim-card/osmo-remsim>.

Documentation
-------------

The User Manual is [optionally] built in PDF form as part of the build process.

A pre-rendered PDF version of the current `master` can be found at
[User Manual](https://downloads.osmocom.org/docs/latest/osmo-remsim-usermanual.pdf).


Forum
-----

We welcome any osmo-remsim related discussions in the
[SIM Card Technology](https://discourse.osmocom.org/c/sim-card-technology/)
section of the osmocom discourse (web based Forum).


Mailing List
------------

There is no separate mailing list for this project. However,
discussions related to pySim are happening on the simtrace
<simtrace@lists.osmocom.org> mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/simtrace> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.


Issue Tracker
-------------

We use the [issue tracker of the osmo-remsim project on osmocom.org](https://osmocom.org/projects/osmo-remsim/issues) for
tracking the state of bug reports and feature requests.  Feel free to submit any issues you may find, or help
us out by resolving existing issues.


Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We are using a gerrit-based patch review process explained at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit>
