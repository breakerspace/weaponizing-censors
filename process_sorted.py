"""
Helper processing script for processing scan files
"""

import os
import tqdm
import sys
import argparse
import subprocess as sp


def get_len(f):
    """
    Returns number of lines in the given file
    """
    return int(sp.check_output(["wc", "-l", f]).decode().split()[0])


def process_file(args):
    """
    Processes given file
    """
    info = {}
    info["total_bytes_from_all_ips"] = 0
    info["total_packets_from_all_ips"] = 0
    info["total_bytes_from_amplifying_ips"] = 0
    info["total_packets_from_amplifying_ips"] = 0
    info["total_ips"] = 0
    info["total_amplifying_ips"] = 0
    flags = {}
    size = args["size"]
    to_analyze = args["file"]
    print("Calculating total length of file to analyze:")
    length = get_len(to_analyze)
    print("%d total packets to analyze." % length)
    pbar = tqdm.tqdm(total=length, leave=False)
    d = args["delimeter"]
    with open(to_analyze, "r") as fd:
        line = fd.readline()
        ip, length, _, _, _ = line.split(d)
        out_file = to_analyze.replace(".csv", "") + "_total_by_ip.txt"
        with open(out_file, "w") as out_fd:
            last_ip = ip
            total_len = 0
            total_packets = 0
            while line:
                pbar.update(1)
                ip, length, _, pktflags, _ = line.split(d)
                if ip == "addr" or length == "len": #skip csv format line
                    line = fd.readline()
                    continue
                if pktflags not in flags:
                    flags[pktflags] = 0
                flags[pktflags] += 1
                if ip == last_ip: #encounter same ip, update totals accordingly
                    total_len += int(length)
                    total_packets += 1
                else: #encounter new ip, write info for last ip and start count for new ip
                    out_fd.write("%d %s %d\n" % (total_len, last_ip, total_packets))
                    info["total_bytes_from_all_ips"] += total_len
                    info["total_packets_from_all_ips"] += total_packets
                    info["total_ips"] += 1
                    if total_len > size:
                        info["total_bytes_from_amplifying_ips"] += total_len
                        info["total_packets_from_amplifying_ips"] += total_packets
                        info["total_amplifying_ips"] += 1
                    total_len = int(length)
                    total_packets = 1
                    last_ip = ip
                line = fd.readline()
            if ip != "saddr":
                out_fd.write("%d %s %d\n" % (total_len, ip, total_packets))
                info["total_bytes_from_all_ips"] += total_len
                info["total_packets_from_all_ips"] += total_packets
                info["total_ips"] += 1
                if total_len > size:
                    info["total_bytes_from_amplifying_ips"] += total_len
                    info["total_packets_from_amplifying_ips"] += total_packets
                    info["total_amplifying_ips"] += 1

    pbar.close()
    info["flags"] = flags
    return info


def get_args():
    """
    Parses args
    """
    parser = argparse.ArgumentParser(description='Calculates the number of packets and bytes associated with each IP address in given file. Assumes the IPs are already sorted.')
    parser.add_argument('-f', '--file', action='store', required=True)
    parser.add_argument('-s', '--size', action='store', type=int, required=True)
    parser.add_argument('-d', '--delimeter', action='store', default=',')
    return parser.parse_args()


if __name__ == "__main__":
    process_file(vars(get_args()))
