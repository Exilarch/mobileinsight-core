Failure Diagnosis with MobileInsight
==============

Mentor: Yunqi Guo [guoyunqi@gmail.com]

## Introduction

In this project, I aim to detect cellular network failure cases, primarily for procedures related to EPS mobility management (EMM). In order to do this, I use MobileInsight, a package for mobile network monitoring and analysis. I process real-world cellular log files with MobileInsight and group failures by category, then store it into the KPI infrastructure built into MobileInsight.

The procedures that I performed failure diagnosis on were identification, authentication, security mode control, GUTI reallocation, attach, detach, and tracking area update. Here is a brief description of each type of EMM procedure:

Identification: Network requests user device to provide unique identification for itself

Authentication: Network and user device must undergo mutual authentication with an agreed-upon key

Security mode control: Initialize the usage of an EPS security context

GUTI reallocation: Network allocates a Globally Unique Temporary Identifier (GUTI) to the user device

Attach: A user device requests registration for a particular network

Detach: A user device is deregistered for a particular network

Tracking Area Update: The user device's tracking area is different from the previously registered cell and must be updated

## Installation

In order to detect failures, we first need to install MobileInsight.
Please install the MobileInsight dependencies before MobileInsight installation. Dependencies are located in the section below this.

The Windows installation is via the virtual machine from [`mobileinsight-dev`](https://github.com/mobile-insight/mobileinsight-dev).

For macOS and Ubuntu, clone/download the git repository to user local folder.
Then run the corresponding installation script (note: do not run with root privileges):

    ./install-macos.sh (macOS)
    ./install-ubuntu.sh (Ubuntu)

The install script will install MobileInsight package to your `PYTHONPATH`, install MobileInsight GUI to `/usr/local/bin/mi-gui`, and run an offline analysis example at the end.

Next, to run the analyzers I developed, run the corresponding script:

    ./test-failures.sh

The analyzers I developed will be created and ran to detect failures for four sample logs. If you would like to run other logs, run kpi-manager-test-fr.py and pass in the appropriate log(s) that you wish to test.

## Failure diagnosis background

These are a description of the possible failures maintained in kpi_measurements:

COLLISION: The ongoing EMM procedure of this analyzer encounters a collision with another EMM procedure of potentially higher priority

CONCURRENT: Either an ongoing tracking area update procedure or attach procedure has encountered a new tracking area update or attach procedure that is distinct from its currently pending procedure.

DETACH: The ongoing EMM procedure of this analyzer has encountered a detach with certain information elements that require the EMM procedure to abort

EMM: The ongoing EMM procedure of this analyzer has encountered a failure related to the EMM cause information element

HANDOVER: An ongoing EMM procedure has experienced a handover failure, which can be traced through RRC layer messages

MAC: The authentication procedure has experienced a MAC failure

NON_EPS: The authentication procedure has received a failure that non-EPS authentication is unacceptable

PROTOCOL_ERROR: A protocol error has been received during an ongoing EMM procedure

SYNCH: The authentication procedure has experienced a synch failure

TRANSMISSION_TAU: An EMM procedure initiated by Tracking Area Update has experienced transmission failure

TRANSMISSION_SERVICE: An EMM procedure initiated by Service Request has experienced transmission failure

TIMEOUT: The associated timer for the ongoing EMM procedure of this analyzer has timed out five times, and so the EMM procedure will abort.

UNAVAILABLE: The requested identity for the identification procedure has been declared unavailable.

Now, I will list the analyzers I developed in question as well as their potential failures:

identification_fr_analyzer.py (COLLISION, CONCURRENT, HANDOVER, TIMEOUT, TRANSMISSION_SERVICE, TRANSMISSION_TAU, UNAVAILABLE)

auth_fr_analyzer.py (EMM, HANDOVER, MAC, NON_EPS, SYNCH, TIMEOUT, TRANSMISSION_SERVICE, TRANSMISSION_TAU)

security_mode_control_fr_analyzer.py (COLLISION, HANDOVER, TIMEOUT, TRANSMISSION_SERVICE, TRANSMISSION_TAU)

guti_reallocation_fr_analyzer.py (COLLISION, HANDOVER, TIMEOUT)

attach_fr_analyzer.py (CONCURENT, DETACH, EMM, PROTOCOL_ERROR, TIMEOUT)

detach_fr_analyzer.py (COLLISION, EMM, HANDOVER, TIMEOUT)

tau_fr_analyzer.py (CONCURRENT, DETACH, EMM, HANDOVER, PROTOCOL_ERROR, TIMEOUT)

These analyzers are all located in mobileinsight-core/mobile_insight/analyzer/kpi

## MobileInsight dependencies

MobileInsight builds on top of `pyserial` and `crcmod`, which can be installed using `pip`:

    pip install pyserial
    pip install crcmod

The GUI of MobileInsight requires `matplotlib` and `wxPython`. `matplotlib` can be installed via `pip`:

    pip install matplotlib

`wxPython` can be installed using Homebrew (macOS) or apt-get (Ubuntu).

    brew install wxpython (macOS)
    apt-get install python-wxgtk3.0 (Ubuntu)


## Upgrade to New Version

Old version of `mobileInsight-core` may have installed Wireshark and Glib libraries under the `/usr/lib` folder. The installation script will auto handle the uninstallation of the old version. If you encounter issues, you may execute the uninstallation script manually to remove them. Please run the uninstallation script with __root__ priviledge to perform proper clean up.

    sudo ./uninstall.sh
