
## Measuring kernel CPU usage of a system:

```bash
vmstat 1 | awk '{print $14}'
```

## Measuring cpu/mem of processes :

- install python requirements
```bash
sudo pip3.8 install -r requirements.txt
```

- run psrecordcsv.py for pid 9999 for 30 seconds on interface eth0:

```bash
sudo python3.8 psrecordcsv.py 9999 --duration 30 --log testlog.log --plot testimage.png --interface eth0 --enable-flows    
```

## Getting flamegraph for ebpf app:
Install bcc-tools (https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary) and flamegraph:
```bash
git clone https://github.com/brendangregg/FlameGraph
```

Run profile tool:
```bash
sudo /usr/share/bcc/tools/profile  -adf -K 10 > out.profile
```

Generate flamegraph:
```bash
./FlameGraph/flamegraph.pl --color=java < out.profile > out.svg
```
