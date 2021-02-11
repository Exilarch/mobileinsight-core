Failure Diagnosis with MobileInsight
==============

Mentor: Yunqi Guo [guoyunqi@gmail.com]

## Introduction

In this project, I aim to detect cellular network failure cases, primarily for procedures related to EPS mobility management (EMM). In order to do this, I use MobileInsight, a package for mobile network monitoring and analysis. I process real-world cellular log files with MobileInsight and group failures by category, then store it into the KPI infrastructure built into MobileInsight.

The procedures that I performed failure diagnosis on were identification, authentication, security mode control, GUTI reallocation, attach, detach, and tracking area update.

## Installation

In order to detect failures, we first need to install MobileInsight.
Please install the MobileInsight dependencies before MobileInsight installation. Dependencies are located in the section below this.

The Windows installation is via the virtual machine from [`mobileinsight-dev`](https://github.com/mobile-insight/mobileinsight-dev).

For macOS and Ubuntu, clone/download the git repository to user local folder.
Then run the corresponding installation script (note: do not run with root privileges):

    ./install-macos.sh (macOS)
    ./install-ubuntu.sh (Ubuntu)

The install script will install MobileInsight package to your `PYTHONPATH`, install MobileInsight GUI to `/usr/local/bin/mi-gui`, and run an offline analysis example at the end.

Next, move these files out of the repository folder:

kpi-manager-test.py

auth_sample.mi2log

attach_sample.mi2log

tau_sample.mi2log

detach_sample.mi2log

Then run kpi-manager-test.py with proper arguments. See comments in kpi-manager-test.py for more instructions.
The analyzers I developed will be created and ran to detect failures for the cellular network log(s) passed in.

The analyzers I developed in question are:

identification_analyzer.py

auth_fr_analyzer.py

security_mode_control_fr_analyzer.py

guti_reallocation_fr_analyzer.py

attach_fr_analyzer.py

detach_analyzer.py

tau_fr_analyzer.py

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
