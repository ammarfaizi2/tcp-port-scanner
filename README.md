
# TCP Port Scanner
Reliable multithreaded TCP port scanner.

# How does it work?
This scanner will try to call `connect(2)` to the target host. If the scanner gets `ECONNREFUSED`, it is probably the target port not blocked by the firewall, there is just no service is bound to the such port.

If the connect success, the scanner will try to send some payload and check whether there is a response from the destination port.

All necessary information will be stored in directory with name target host. If the directory does not exist, the scanner will create it automatically.

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
