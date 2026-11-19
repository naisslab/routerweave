# Routerweave shared traffic processing

Use Python 3.10 or newer. Run the commands from the directory containing this README. The module uses only the Python standard library.

## Reproduce the example

The included synthetic capture contains eight frames. To extract IP packets for the example device, use the following command.

```sh
python -m shared_traffic examples/dns_ttl.pcap --device sensor --ip 192.0.2.10 --summary
```

Expect six JSON Lines records for frames 2, 4, 5, 6, 7 and 8. The DNS answer in frame 5 is valid for two seconds. Frame 6 has `service_source="dns"`. At frame 7 the TTL expires and `service_source` is null.

Add `--flows` to aggregate the same packets into bidirectional TCP/UDP flows.

```sh
python -m shared_traffic examples/dns_ttl.pcap --device sensor --ip 192.0.2.10 --flows --summary
```

Expect two flow records covering five packets. Frame 8 is ICMP and appears only in the packet output. Both commands write records to standard output and summary counts to standard error.

## Use your own capture

Replace the example path with a classic PCAP 2.4 file using Ethernet, Linux SLL or SLL2 framing. Set `--device` to a label of your choice and `--ip` to the device address at capture time. For Ethernet captures, you can also select the device with `--mac`. Repeat an address option if the device used several addresses.

`frame` is the original frame number. `time_ns` is the capture timestamp in Unix nanoseconds. Direction is relative to the selected device. For truncated frames, `wire_bytes` gives the original frame length and `captured_bytes` gives the number of bytes saved in the file.
