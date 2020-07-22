
# TCP Port Scanner
Reliable multithreaded TCP port scanner.

# How does it work?
This scanner will enumerate the target host's port. The scanner will call connect(2) to the target host with the port start from port 1 to 65535.

If the scanner gets `ERRCONNREFUSED` then, we assume that the target port is not behind the firewalled environment, in the general case, this condition occurs when there is no service that binds to such port.

If the scanner gets `EINPROGRESS` or `ERRTIMEDOUT` then, it means the scanner has reached its time limit (can be set in parameter). In the general case, this condition occurs when the target host is dropping our packet, so we assume that the port is behind a firewalled environment.

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
    -t|--threads <num>	Number of threads (default: 8)
    -h|--host <host>	Target host (IPv4)
    -v|--verbose	Verbose output (use more -v to increase verbose level)
    -r|--recv-timeout	recv(2) timeout (default: 5)
    -s|--send-timeout	send(2) timeout, this affects connect(2) too (default: 5)
```

# Example Usage
```sh
# It will create directory with name "reports/157.240.13.35"
./scanner -h 157.240.13.35 -t 4 -r 10 -s 10 -vvv


# Check the reports
cd reports/157.240.13.35/000_report.txt | sort;
```

# License
The software is licensed under the MIT license.
