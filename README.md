# weaponizing-censors

## 📝 Summary 

## 🏃 Running zmap

Example on how to build `zmap` and run the `forbidden_scan` module: 

```
$ cmake . && make -j4  && sudo src/zmap -M forbidden_scan -p 80 $IP/32 -f "saddr,len,payloadlen,flags,validation_type" -o validation_test.csv -O csv -P 2
```

## 📃 License

No license is included in this repository, since this repository is largely just a pointer to other repositories. Each of those other repositories contains its own license - please consult each for license information. 
