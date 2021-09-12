# weaponizing-censors [![badge](https://img.shields.io/badge/In%20Proceedings-USENIX%20Security%202021-blue.svg)](https://www.usenix.org/conference/usenixsecurity21/presentation/bock)

Censors pose a threat to the entire Internet. In this work, we show that censoring middleboxes and firewalls can be weaponized by attackers to launch unprecedented reflected denial of service attacks. We find hundreds of thousands of IP addresses that offer amplification factors greater than 100× and IP addresses that technically offer _infinite amplification_. 

This is the code repository for the USENIX Security 2021 paper, "[Weaponizing Middleboxes for TCP Reflected Amplification](https://geneva.cs.umd.edu/papers/usenix-weaponizing-ddos.pdf)". 

This repository contains submodules for our two forks of ZMap, a submodule to the main [Geneva](https://github.com/Kkevsterrr/geneva) repository containing the plugin used to identify the amplifying sequences, and processing scripts for analyzing scan results.  

Amplification attacks are not the only way that censors pose a threat to those living outside their borders. See our concurrent work from WOOT 2021 on [weaponizing censors for availability attacks](https://geneva.cs.umd.edu/papers/woot21-weaponizing-availability.pdf) and its [repository](https://github.com/breakerspace/weaponizing-residual-censorship/). 

## 📝 Abstract

Reflective amplification attacks are a powerful tool in the arsenal of a DDoS attacker, but to date have almost exclusively targeted UDP-based protocols. In this paper, we demonstrate that non-trivial TCP-based amplification is possible and can be orders of magnitude more effective than well-known UDP-based amplification. By taking advantage of TCP-non-compliance in network middleboxes, we show that attackers can induce middleboxes to respond and amplify network traffic. With the novel application of a recent genetic algorithm, we discover and maximize the efficacy of new TCP-based reflective amplification attacks, and present several packet sequences that cause network middleboxes to respond with substantially more packets than we send.

We scanned the entire IPv4 Internet to measure how many IP addresses permit reflected amplification. We find hundreds of thousands of IP addresses that offer amplification factors greater than 100×. Through our Internet-wide measurements, we explore several open questions regarding DoS attacks, including the root cause of so-called "mega amplifiers". We also report on network phenomena that causes some of the TCP-based attacks to be so effective as to technically have _infinite_ amplification factor (after the attacker sends a constant number of bytes, the reflector generates traffic indefinitely). 

## 🧪 Try it yourself

To clone the repo, make sure you clone all of the submodules present.

```
# git clone --recursive https://github.com/breakerspace/weaponizing-censors
```

Disclaimer: this code will intentionally try to trigger real censoring middleboxes and can generate large volumes of traffic (both on its own, and with the presence of amplifiers). Understand the risks of running it in your network before doing so. 

## 🕵️‍♀️ Finding Amplifiers: ZMap Forks

We scanned the entire IPv4 Internet dozens of times to find IP addresses with middleboxes on their path that could be weaponized. To find these, we created two custom forks of the open-source scanning tool [`ZMap`](https://github.com/zmap/zmap). ZMap is a fast single packet network scanner designed for Internet-wide network surveys. We modified ZMap first to add a new probe module (the `forbidden_scan` module defined in `src/probe_modules/module_forbidden_scan.c`), and then created a second fork to add the ability to craft two distinct packets for each probe (this enables us to send a custom `SYN` packet, followed by a second custom packet containing a well-formed HTTP `GET` request). 

The submodule `zmap` in this repository is for single packet scans (the `SYN`, `PSH`, or `PSH+ACK` scans from our paper) and `zmap_multiple_probes` (for the `SYN; PSH` or `SYN; PSH+ACK` scans from our paper).

The module has multiple options compiled in, including the `Host:` header included in the payload. To change any of the following options, edit the `module_forbidden_scan.c` file located in `src/probe_modules` and recompile ZMap to use. 

## 🏃 Running ZMap

Example on how to build `zmap` and run the `forbidden_scan` module to scan a single IP address and record the responses received: 

```
$ IP=<IP address to scan here>
$ cmake . && make -j4  && sudo src/zmap -M forbidden_scan -p 80 $IP/32 -f "saddr,len,payloadlen,flags,validation_type" -o scan.csv -O csv 
```

The output of the scan is a csv file called `scan.csv`. For each packet that ZMap identified as a response to our scan, the output file will contain the `src` IP address, the IP length of the packet, the length of the payload itself, the TCP flags, and the _validation_type_ (the reason the probe treated the incoming packet as a response to a probe). 

This module can be used to test firewalls or other middleboxes to see if they are vulnerable to this attack. 

Also in this repsitory is a helper script `scan_all.py`, which can be used to automate multiple ZMap scans with different scanning parameters.  

## 🔬 Processing Scan Results

Included in this repository are two helper scripts to process the results of a ZMap scan. The main processing script is `stats.py`, which will consume the output of ZMap and generate graphs and summary statistics about the scan. See the below example of the `stats.py` script processing a `scan.csv` file (note the IP addresses have been anonymized). 

```    
# python3 stats.py scan.csv 149
Processing scan data assuming attacker sent 149 bytes per IP.
Initializing analysis of scan.csv
Calculating total length of file to analyze:
949099449 total packets to analyze.
  - Unique responding IPs: 362138621
  - Number of amplifying IP addresses: 218015761
  - Total number of bytes sent by amplifying IP addresses: 45695690843
  - Average amplification rate from amplifying IP addresses: 1.407000
  - Highest total data received by IP:
        7632101 96.96.96.96 141334
        9788625 97.97.97.97 181270
        44365380 98.98.98.98 142200
        238162104 99.99.99.99 1011556
  - Highest total packets received by IP:
        7360299 1.1.1.1 136301
        8040711 2.2.2.2 148901
        8186133 3.3.3.3 151594
        238162104 4.4.4.4 1011556
  - Flags on packets sent by responders:
    + 472: S
    + 119609984: R
    + 680892582: RA
    + 12: FSPA
    + 1: SPUE
    + 2: PAU
    + 1: SUEC
    + 1: FAU
    + 1: PAUE
    + 1: SRPAUEC
    + 7217: FRPA
    + 4734607: FA
    + 5540525: RPA
    + 3687478: PA
    + 58615499: SA
    + 11928812: FPA
    ...
  - CDF of number of packets sent: scan_packets_cdf.eps
  - CDF of bytes sent: scan_bytes_cdf.eps
  - CDF of amplification rate: scan_amplification_cdf.eps
```

## 📃 License

This repository is licensed under BSD 3-Clause license. Please note that this repository contains multiple submodule pointers to other repositories, each of which contains its own license. Please consult each for license information. 

## 📑 Citation

To cite this paper, please use the Bibtex [here](https://www.usenix.org/biblio/export/bibtex/272318).
