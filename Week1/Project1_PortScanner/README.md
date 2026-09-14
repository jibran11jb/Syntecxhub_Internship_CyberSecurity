# TCP Port Scanner

## Internship Project 1 – Cyber Security

### Introduction

This project is a TCP port scanner developed in Python as part of the Cyber Security internship.

The purpose of the project is to understand basic socket programming, TCP connections, port scanning, concurrency using threads, exception handling, and result logging.

## Features

* Scan a single host
* Scan a range of TCP ports
* Detect open ports
* Detect closed ports
* Handle connection timeouts
* Handle socket errors
* Use multiple threads for faster scanning
* Display scan results in the terminal
* Save scan results to a log file
* Command-line options for customization

## Technologies Used

* Python 3
* Socket Programming
* TCP
* ThreadPoolExecutor
* Command-line arguments

## How to Run

Basic scan:

```bash
python port_scanner.py 127.0.0.1
```

Scan ports 1 to 100:

```bash
python port_scanner.py 127.0.0.1 --start 1 --end 100
```

Specify the number of threads:

```bash
python port_scanner.py 127.0.0.1 --start 1 --end 100 --workers 50
```

Specify a timeout:

```bash
python port_scanner.py 127.0.0.1 --start 1 --end 100 --timeout 1
```

## Output

The scanner displays the status of each port:

* OPEN – a TCP connection was successfully established.
* CLOSED – the connection was refused.
* TIMEOUT – the connection did not respond within the specified time.
* ERROR – another socket error occurred.

The results are also saved in `scan_results.txt`.

## Learning Outcomes

Through this project, I learned:

1. Basic Python socket programming.
2. How TCP connections can be tested.
3. How ports are checked for availability.
4. How concurrency can improve scanning speed.
5. How to use threads with `ThreadPoolExecutor`.
6. How to handle socket exceptions.
7. How to save program output into a log file.
8. How to create command-line options in Python.

## Ethical Use

This tool is intended for educational and authorized security testing only.

It should only be used against localhost, systems owned by the user, or systems for which explicit permission has been provided.
