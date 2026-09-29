# Syntecxhub Internship — Project 1: SQL Injection Scanner

A small Python security-testing tool for the Syntecxhub Cyber Security internship.

## Objective

The internship task asks for a script that:

- probes web inputs for common SQL injection patterns;
- sends crafted requests;
- detects vulnerability indicators;
- reports findings;
- logs results;
- uses basic concurrency and rate limiting.

The scanner is intentionally limited to **localhost/private targets** for authorized testing.

## Safety

Only test:

- DVWA running locally;
- another local application you own;
- an explicitly authorized private test server.

Do not scan public websites without written authorization.

The scanner does not dump database contents, bypass authentication, or attempt destructive SQL commands.

## Requirements

- Python 3.10+
- `requests`

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

## Example with DVWA

If DVWA is running at:

```text
http://127.0.0.1/vulnerabilities/sqli/?id=1
```

run:

```bash
python sqli_scanner.py "http://127.0.0.1/vulnerabilities/sqli/?id=1"
```

If the application requires a specific parameter:

```bash
python sqli_scanner.py "http://127.0.0.1/test?id=1" --params id
```

For a local HTTPS lab using a self-signed certificate:

```bash
python sqli_scanner.py "https://127.0.0.1/test?id=1" --insecure
```

## Concurrency and rate limiting

The default configuration uses:

- 3 worker threads;
- a global limit of 2 requests/second.

You can change them:

```bash
python sqli_scanner.py "http://127.0.0.1/test?id=1" --threads 5 --rate 3
```

## Output

The scanner creates:

```text
results.csv
```

with:

- tested URL;
- parameter;
- payload;
- HTTP status;
- detection indicator;
- short evidence.

## Detection approach

The scanner uses two basic indicators:

1. **Known SQL error messages**  
   Examples include common MySQL, SQLite, PostgreSQL, Oracle, SQL Server, and ODBC error fragments.

2. **Response-size anomaly**  
   A payload causing a large response-size change compared with a baseline is reported as a warning signal.

A response-size anomaly is **not proof** of SQL injection and should be manually verified.

## Suggested submission structure

```text
Syntecxhub_SQL_Injection_Scanner/
├── sqli_scanner.py
├── requirements.txt
├── README.md
├── .gitignore
└── sample_results.csv
```

Do not commit real credentials, cookies, tokens, or private application data.
