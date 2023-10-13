
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