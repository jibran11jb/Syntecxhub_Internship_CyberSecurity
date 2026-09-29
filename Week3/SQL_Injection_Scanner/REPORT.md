# Project 1 Report — SQL Injection Scanner

## 1. Project Objective

Build a Python script that probes web inputs for common SQL injection patterns, sends crafted requests, detects vulnerability indicators, reports findings, logs results, and uses basic concurrency and rate limiting.

## 2. Tools and Technologies

- Python 3
- Requests
- ThreadPoolExecutor
- CSV
- Logging
- DVWA/local test application

## 3. Testing Environment

Target: `127.0.0.1` / localhost

Application: ______________________________

Test date: ________________________________

## 4. Methodology

1. Validate that the target is local/private.
2. Identify query-string parameters.
3. Request a baseline response.
4. Send non-destructive SQLi test payloads.
5. Check responses for common SQL error indicators.
6. Compare response size with the baseline.
7. Run parameter checks concurrently.
8. Apply a global request-rate limit.
9. Save findings to CSV.

## 5. Payload Categories

The scanner uses simple quote-based and boolean-style test strings. It does not attempt database extraction or destructive SQL commands.

## 6. Results

Number of indicators: __________

Vulnerable/test parameter(s): ______________________________

Evidence: _________________________________________________

## 7. Limitations

- Error messages may be hidden by the application.
- Response-size changes can have legitimate causes.
- An indicator does not prove exploitability.
- The scanner currently focuses on URL query parameters and GET requests.
- Manual verification is required.

## 8. Ethical Considerations

Testing must be restricted to systems owned by the tester or systems for which explicit authorization has been provided. The project is intended for DVWA and local test applications.

## 9. Conclusion

The project demonstrates basic automated SQL injection indicator detection, logging, concurrency, and rate limiting while keeping testing within an authorized local/private environment.
