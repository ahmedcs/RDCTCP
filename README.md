# RDCTCP
RDCTCP is a (Virtualized) Receive Window based implementation of DCTCP in data centre networks. 
Specifically, it aims at building a hypervisor based (end-to-end) scheme to enforce DCTCP at the hypervisor level and leverage the performance benefits regardless of the congestion control variant used by the VM. 

It is implemented as a hardware prototype in Linux Kernel as a Load-able Kernel Module and NetFilter framework is used for packet interception.

# Installation Guide
Please Refer to the \[[InstallME](InstallME.md)\] file for more information about installation and possible usage scenarios.

# Running experiments

To run an experiment of DCTCP, install DCTCP on the end-hosts then issue the following:

```
cd experiments
./run_incast.sh 
```
Or to an experiment involving incast and buffer bloating
```
cd experiments
./run_bloat_incast.sh 
```
For more details on the experiments, refer the scripts and adjust them according to your testbed
#Feedback
I always welcome and love to have feedback on the program or any possible improvements, please do not hesitate to contact me by commenting on the code [Here](https://ahmedcs.github.io/RDCTCP-post/) or dropping me an email at [ahmedcs982@gmail.com](mailto:ahmedcs982@gmail.com). **PS: this is one of the reasons for me to share the software.**  

**This software will be constantly updated as soon as bugs, fixes and/or optimization tricks have been identified.**


# License
This software including (source code, scripts, .., etc) within this repository and its subfolders are licensed under CRAPL license.

**Please refer to the LICENSE file \[[CRAPL LICENCE](LICENSE)\] for more information**


# CopyRight Notice
The Copyright of this repository and its subfolders are held exclusively by "Ahmed Mohamed Abdelmoniem Sayed", for any inquiries contact me at ([ahmedcs982@gmail.com](mailto:ahmedcs982@gmail.com)).

Any USE or Modification to the (source code, scripts, .., etc) included in this repository has to cite the following PAPERS:  

<!--1- Ahmed M. Abdelmoniem and Brahim Bensaou, “Curbing Timeouts for TCP- Incast in Data Centers via A Cross-Layer Faster Recovery Mechanism, in Proceedings of IEEE INFOCOM 2018, Honolulu, HI, USA, Apr-2018.--> 
 
<!--2- Ahmed M Abdelmoniem, Brahim Bensaou, "End-host Timely TCP Loss Recovery via ACK Retransmission in Data Centres", Technical Report, HKUST-CS17-02, Hong Kong, 2017.--> 

**Notice, the COPYRIGHT and/or Author Information notice at the header of the (source, header and script) files can not be removed or modified.**


# Published Paper
<!--To understand the framework and proposed solution, please read the paper \[[T-RACKs INFOCOM paper PDF](download/TRACKs-Paper.pdf)\] and technical report \[[T-RACKs Tech-Repo PDF](download/TRACKs-Report.pdf)\]-->
