"""
Processing pipeline for output scan. Assumes a scan csv file output by zmap, and you supply it
the number of bytes sent by each probe.

Due to the sheer size of the scan files, we can't do normal processing with Python; instead,
this script automates a series of bash commands.

Prints results like this (IP addresses anonymized)::

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
      - CDF of number of packets sent: scan_packets_cdf.eps
      - CDF of bytes sent: scan_bytes_cdf.eps
      - CDF of amplification rate: scan_amplification_cdf.eps

"""
import sys
import os
import subprocess as sp
from scapy.all import TCP

import process_sorted

VERBOSE=False

if len(sys.argv) < 3:
    print("Usage: %s <file> <sent_len>" % __file__)
    exit()

sent_len = int(sys.argv[2])

print("Processing scan data assuming attacker sent %d bytes per IP." % sent_len)

def run_cmd(cmd):
    """
    Prints and runs cmd with os.system.
    """
    if VERBOSE:
        print("    " + cmd)
    try:
        out = sp.check_output(cmd, shell=True)
    except sp.CalledProcessError as exc:
        out = exc.output
    return out

testfile = sys.argv[1]
if not testfile.endswith(".csv"):
    print("Not a csv file.")
    exit()

print("Initializing analysis of %s" % testfile)
basename = testfile.replace(".csv", "")

outfile = open("%s_analysis.txt" % basename, "w")

def dprint(msg, **kwargs):
    print(msg, **kwargs)
    outfile.write(msg+"\n")


if not os.path.exists("%s_sorted_by_ip.csv" % basename):
    run_cmd("sort -k1,1 -t\",\" %s --parallel 4 > %s_sorted_by_ip.csv" % (testfile, basename))
else:
    print("%s_sorted_by_ip.csv already exists, skipping regeneration" % basename)

# This will write a file %s_sorted_by_ip_total_by_ip.txt
args = {
    "size": sent_len,
    "file": "%s_sorted_by_ip.csv" % basename,
    "delimeter": ","
}

info = process_sorted.process_file(args)
total_ips = info["total_ips"]
total_amplifiers = info["total_amplifying_ips"]
total_bytes_from_amplifiers = info["total_bytes_from_amplifying_ips"]

dprint("  - Unique responding IPs: %d" % total_ips)
dprint("  - Number of amplifying IP addresses: %d" % total_amplifiers)
dprint("  - Total number of bytes sent by amplifying IP addresses: %d" % total_bytes_from_amplifiers)
dprint("  - Average amplification rate from amplifying IP addresses: %f" % round(total_bytes_from_amplifiers/max(total_amplifiers * sent_len, 1), 3))

dprint("  - Highest total data received by IP: ")
if not os.path.exists("%s_total_by_ip_bytes.txt" % basename):
    run_cmd("sort -k1 -n --parallel 4 %s_sorted_by_ip_total_by_ip.txt > %s_total_by_ip_bytes.txt" % (basename, basename))
dprint(run_cmd("tail %s_total_by_ip_bytes.txt" % basename).decode('utf-8').strip())

if not os.path.exists("%s_total_by_ip_bytes_reverse.txt" % basename):
    run_cmd("sort -nrk1 --parallel 4 %s_total_by_ip_bytes.txt > %s_total_by_ip_bytes_reverse.txt" % (basename, basename))

dprint("  - Highest total packets received by IP: ")
if not os.path.exists("%s_total_by_ip_packets.txt" % basename):
    run_cmd("sort -k3 -n --parallel 4 %s_sorted_by_ip_total_by_ip.txt > %s_total_by_ip_packets.txt" % (basename, basename))
dprint(run_cmd("tail %s_total_by_ip_packets.txt" % basename).decode('utf-8').strip())

#if not os.path.exists("%s_total_by_amplifying_ips_sorted" % basename):
#    run_cmd("cat %s_total_by_ip_bytes.txt | awk '{if ($1 > %d) {print}}' > %s_total_by_amplifying_ips_sorted.txt" % (basename, sent_len, basename))

dprint("  - Flags on packets sent by responders: ")
for flag in info["flags"]:
    count = info["flags"][flag]
    if flag == "flags":
        continue
    flag = int(flag)
    f = str(TCP(flags=flag).flags)
    dprint("    + %s: %s" % (count, f))

dprint("  - CDF of number of packets sent: ", end="")
plot_cmd = "gnuplot -e \"load 'style.gnu'; set output '%s_packets_cdf.eps'; set xlabel \\\"\{/Helvetica-Bold Packets Sent\}\\\"; set ylabel \\\"\{/Helvetica-Bold Cumulative Fraction of Hosts\}\\\"; set logscale x; plot '%s_total_by_ip_packets.txt' u 3:(\$0/%d) w st ls 1 ti ''\"" % (basename, basename, total_ips)
run_cmd(plot_cmd)
dprint("%s_packets_cdf.eps" % basename)
dprint("  - CDF of bytes sent: ", end="")
plot_cmd = "gnuplot -e \"load 'style.gnu'; set output '%s_bytes_cdf.eps'; set xlabel \\\"\{/Helvetica-Bold Bytes Sent\}\\\"; set ylabel \\\"\{/Helvetica-Bold Cumulative Fraction of Hosts\}\\\"; set logscale x; plot '%s_total_by_ip_bytes.txt' u 1:(\$0/%d) w st ls 1 ti ''\"" % (basename, basename, total_ips)
run_cmd(plot_cmd)
dprint("%s_bytes_cdf.eps" % basename)
dprint("  - CDF of amplification rate: ", end="")
plot_cmd = "gnuplot -e \"load 'style.gnu'; set output '%s_amplification_cdf.eps'; set xlabel \\\"\{/Helvetica-Bold Amplification Rate\}\\\"; set ylabel \\\"\{/Helvetica-Bold Cumulative Fraction of Hosts\}\\\"; set logscale x; plot '%s_total_by_ip_bytes.txt' u (\$1/%d):(\$0/%d) w st ls 1 ti ''\"" % (basename, basename, sent_len, total_ips)
run_cmd(plot_cmd)
dprint("%s_amplification_cdf.eps" % basename)
