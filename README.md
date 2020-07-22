
# TCP Port Scanner


# Installation
```sh
git clone https://github.com/ammarfaizi2/tcp-port-scanner;
cd tcp-port-scanner;
make;
```

# Usage
```
Usage: ./scanner [options]
  Options:
    -t|--threads <num>	Number of threads (default: 1)
    -h|--host <host>	Target host (IPv4)
    -v|--verbose	Verbose output (use more -v to increase verbose level)
    -r|--recv-timeout	recv(2) timeout (default: 5)
    -s|--send-timeout	send(2) timeout (default: 5)
```

# Example Usage
```
./scanner -h 157.240.13.35 -t 4 -r 10 -s 10 -vvv
```

# License
The software is licensed under the MIT license.
