# weaponizing-censors

## 🏃 Running zmap

Example on how to build `zmap` and run the `forbidden_scan` module: 

```
$ cmake . && make -j4  && sudo src/zmap -M forbidden_scan -p 80 $IP/32 -f "saddr,len,payloadlen,flags,validation_type" -o validation_test.csv -O csv -P 2
```
