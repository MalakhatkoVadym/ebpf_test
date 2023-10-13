#!/usr/bin/env python3

from __future__ import (unicode_literals, division, print_function,
                        absolute_import)

from scapy.all import *
import threading
import time
import time
import argparse
import csv
import scipy
from collections import defaultdict

children = []

flow_counts = defaultdict(int)

flows = set()
prev_count = 0
stop_sniff = False


def process_packet(pkt):
    global flows
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            src_port = None
            dst_port = None
        flow = (src_ip, src_port, dst_ip, dst_port, proto)
        flows.add(flow)


def stop_sniffing(pkt):
    return stop_sniff


def count_flows():
    global flows, prev_count
    curr_count = len(flows)
    flows.clear()
    return curr_count


def get_percent(process):
    return process.cpu_percent()


def get_memory(process):
    return process.memory_info()


def all_children(pr):

    global children

    try:
        children_of_pr = pr.children(recursive=True)
    except Exception:  # pragma: no cover
        return children

    for child in children_of_pr:
        if child not in children:
            children.append(child)

    return children


def main():

    parser = argparse.ArgumentParser(
        description='Record CPU and memory usage for a process')

    parser.add_argument('process_id_or_command', type=str,
                        help='the process id or command')

    parser.add_argument('--csv', type=str,
                        help='output the statistics to a csv file')

    parser.add_argument('--interface', type=str,
                        help='network interface to monitor')

    parser.add_argument('--log', type=str,
                        help='output the statistics to a file')

    parser.add_argument('--plot', type=str,
                        help='output the statistics to a plot')

    parser.add_argument('--duration', type=float,
                        help='how long to record for (in seconds). If not '
                             'specified, the recording is continuous until '
                             'the job exits.')

    parser.add_argument('--include-children',
                        help='include sub-processes in statistics (results '
                             'in a slower maximum sampling rate).',
                        action='store_true')

    parser.add_argument(
        '--enable-flows', help='output the flow counts per second to a csv file and flows as X axis', action='store_true')

    args = parser.parse_args()

    # Attach to process
    try:
        pid = int(args.process_id_or_command)
        print("Attaching to process {0}".format(pid))
        sprocess = None
    except Exception:
        import subprocess
        command = args.process_id_or_command
        print("Starting up command '{0}' and attaching to process"
              .format(command))
        sprocess = subprocess.Popen(command, shell=True)
        pid = sprocess.pid

    monitor(pid, logfile=args.log, plot=args.plot, duration=args.duration,
            include_children=args.include_children, interface=args.interface, enable_flows=args.enable_flows)

    if sprocess is not None:
        sprocess.kill()


def get_network_stats(interface):
    import psutil

    net_io = psutil.net_io_counters(pernic=True)
    if interface not in net_io:
        raise ValueError(f"Interface {interface} not found")

    return net_io[interface].bytes_sent, net_io[interface].bytes_recv


def monitor(pid, logfile=None, plot=None, duration=None,
            include_children=False, interface=None, enable_flows=False):

    # We import psutil here so that the module can be imported even if psutil
    # is not present (for example if accessing the version)
    import psutil

    pr = psutil.Process(pid)

    # Record start time
    start_time = time.time()

    if logfile:
        f = open(logfile, 'w', newline='')
        csv_writer = csv.writer(f)
        header = ['ElapsedTime', 'CPU(%)', 'Real(MB)', 'Virtual(MB)']
        if interface:
            header.extend(['Incoming', 'Outgoing'])
            if enable_flows:
                header.extend(['Flows'])
        csv_writer.writerow(header)

    log = {}
    log['times'] = []
    log['cpu'] = []
    log['mem_real'] = []
    log['mem_virtual'] = []
    log['incoming'] = []
    log['outgoing'] = []
    log['flows'] = []

    prev_net_stats = defaultdict(lambda: (0, 0))
    if interface:
        prev_net_stats[interface] = get_network_stats(interface)
        if enable_flows:
            sniff_thread = threading.Thread(target=sniff, kwargs={
                                            "iface": interface, "prn": process_packet, 'stop_filter': stop_sniffing})
            sniff_thread.start()

    try:

        # Start main event loop
        while True:

            # Find current time
            current_time = time.time()

            try:
                pr_status = pr.status()
            except TypeError:  # psutil < 2.0
                pr_status = pr.status
            except psutil.NoSuchProcess:  # pragma: no cover
                break

            # Check if process status indicates we should exit
            if pr_status in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
                print("Process finished ({0:.2f} seconds)"
                      .format(current_time - start_time))
                break

            # Check if we have reached the maximum time
            if duration is not None and current_time - start_time > duration:
                break

            # Get current CPU and memory
            try:
                current_cpu = get_percent(pr)
                current_mem = get_memory(pr)
            except Exception:
                break
            current_mem_real = current_mem.rss / 1024. ** 2
            current_mem_virtual = current_mem.vms / 1024. ** 2

            # Get information for children
            if include_children:
                for child in all_children(pr):
                    try:
                        current_cpu += get_percent(child)
                        current_mem = get_memory(child)
                    except Exception:
                        continue
                    current_mem_real += current_mem.rss / 1024. ** 2
                    current_mem_virtual += current_mem.vms / 1024. ** 2

            if interface:
                curr_net_stats = get_network_stats(interface)
                sent = (curr_net_stats[0] -
                        prev_net_stats[interface][0]) / 125000.0
                recv = (curr_net_stats[1] -
                        prev_net_stats[interface][1]) / 125000.0
                prev_net_stats[interface] = curr_net_stats
                if enable_flows:
                    flow_count = count_flows()

            if logfile:
                row = [current_time - start_time,
                       current_cpu,
                       current_mem_real,
                       current_mem_virtual]
                if interface:
                    row.extend([recv, sent])
                    if enable_flows:
                        row.extend([flow_count])
                csv_writer.writerow(row)

            time.sleep(1)

            # If plotting, record the values
            if plot:
                log['times'].append(current_time - start_time)
                log['cpu'].append(current_cpu)
                log['mem_real'].append(current_mem_real)
                log['mem_virtual'].append(current_mem_virtual)
                if interface:
                    log['incoming'].append(recv)
                    log['outgoing'].append(sent)
                    if enable_flows:
                        log['flows'].append(flow_count)

    except KeyboardInterrupt:  # pragma: no cover
        pass

    if logfile:
        f.close()
    global stop_sniff
    stop_sniff = True

    if plot:

        # Use non-interactive backend, to enable operation on headless machines
        import matplotlib.pyplot as plt
        with plt.rc_context({'backend': 'Agg'}):

            fig = plt.figure()
            ax = fig.add_subplot(1, 1, 1)

            if interface:

                log['total_speed_mbps'] = []
                for i in range(len(log['incoming'])):
                    log['total_speed_mbps'].append(
                        log['incoming'][i] + log['outgoing'][i])

                sorted_arrays = sorted(
                    zip(log['total_speed_mbps'], log['cpu'], log['mem_real']))
                total_speed_mbps, cpus, mem_reals = zip(*sorted_arrays)
                ax.plot(total_speed_mbps,
                        cpus, '-', lw=1, color='r')
                ax.set_ylabel('CPU (%)', color='r')
                ax.set_xlabel('Mb/s')
                ax.set_ylim(0., max(cpus) * 1.2)
                ax2 = ax.twinx()
                ax2.plot(total_speed_mbps,
                         mem_reals, '-', lw=1, color='b')
                ax2.set_ylim(0., max(mem_reals) * 1.2)
                ax2.set_ylabel('Real Memory (MB)', color='b')

                sorted_arrays = sorted(
                    zip(log['flows'], log['cpu'], log['mem_real']))
                flows, cpus, mem_reals = zip(*sorted_arrays)
                ax.plot(flows,
                        cpus, '-', lw=1, color='r')
                if enable_flows:
                    fig2 = plt.figure()
                    ax3 = fig2.add_subplot(1, 1, 1)
                    sorted_arrays = sorted(
                        zip(log['flows'], log['cpu'], log['mem_real']))
                    flows, cpus, mem_reals = zip(*sorted_arrays)
                    ax3.plot(flows,
                             cpus, '-', lw=1, color='r')
                    ax3.set_ylabel('CPU (%)', color='r')
                    ax3.set_xlabel('Flows/s')
                    ax3.set_ylim(0., max(cpus) * 1.2)
                    ax4 = ax3.twinx()
                    ax4.plot(flows,
                             mem_reals, '-', lw=1, color='b')
                    ax4.set_ylim(0., max(mem_reals) * 1.2)
                    ax4.set_ylabel('Real Memory (MB)', color='b')
                    ax3.grid()

                    fig2.savefig('flow_' + plot)

            else:
                ax.plot(log['times'], log['cpu'], '-', lw=1, color='r')
                ax.set_ylabel('CPU (%)', color='r')
                ax.set_xlabel('time (s)')
                ax.set_ylim(0., max(log['cpu']) * 1.2)

                ax2 = ax.twinx()

                ax2.plot(log['times'], log['mem_real'],
                         '-', lw=1, color='b')
                ax2.set_ylim(0., max(log['mem_real']) * 1.2)

                ax2.set_ylabel('Real Memory (MB)', color='b')

            ax.grid()

            fig.savefig(plot)


if __name__ == "__main__":
    main()
