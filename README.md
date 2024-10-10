# BlindBrute - Blind SQL Injection Brute Forcer

BlindBrute is a Python tool designed for performing blind SQL injection attacks. It supports detecting vulnerabilities using a combination of status codes, content length, keyword comparisons, and time-based SQL injection techniques. The tool provides advanced customization through injectable headers, request data, and HTTP request templates, making it highly flexible for various attack scenarios.

## Features

- **Blind SQL Injection**: Performs blind SQL injection attacks using status codes, content length, keyword comparisons, and sleep-based detection.
- **Customizable Payloads**: Supports customizable payloads for headers and request bodies, allowing fine-tuned injections tailored to your specific needs.
- **Threading Support**: Utilizes multithreading to handle concurrent requests, significantly improving performance for large-scale extraction tasks.
- **Dictionary-Based Extraction**: Supports dictionary-based SQL extraction with fallback to character-by-character extraction for optimized data extraction.
- **Binary Search for ASCII Extraction**: Performs binary ASCII extraction to speed up brute-forcing of individual characters.
- **File-Based Request Templates**: Load and parse raw HTTP requests with placeholders for dynamic injection, enabling greater control over your requests.
- **Sleep-Based Detection**: Supports sleep-based time-delay SQL injection techniques for detecting vulnerabilities and extracting data when other methods fail.

## Requirements

- Python 3.6 or higher
- `requests` library
- `argparse` library
- `json` library

Install dependencies using:

```bash
pip install -r requirements.txt
```

## Usage

```bash
Usage:
    python blindbrute.py -u <URL> -t <TABLE> -c <COLUMN> -w <WHERE CLAUSE> [options]

Required Arguments:
    -u, --url                    Target URL
    -t, --table                  Table name from which to extract the data
    -c, --column                 Column name to extract (e.g., Password)
    -w, --where                  WHERE clause (e.g., Username = 'Administrator')

Optional Arguments:
    -ih, --injectable-headers     Injectable headers as key-value pairs 
                                  (e.g., -ih Referer http://example.com)
    -sh, --static-headers         Static headers as key-value pairs that do not contain payloads
                                  (e.g., -sh session_id abcdefg12345)
    -d, --data                   Specify data to be sent in the request body. Changes request type to POST.
    -f, --file                   File containing the HTTP request with 'INJECT' placeholder for payloads
    -m, --max-length             Maximum length of the extracted data (default: 1000)
    -ba, --binary-attack         Use binary search for ASCII extraction
    -da, --dictionary-attack     Path to a wordlist file for dictionary-based extraction
    --level                      Specify the threading level (1-5, default: 2)
                                  Level 1 uses fewer threads; level 5 uses more threads for faster extraction.
    --delay                      Delay in seconds between requests to bypass rate limiting
    --timeout                    Timeout for each request in seconds (default: 10)
    --verbose                    Enable verbose output for debugging
    --true-keywords              Keywords to search for in the true condition response 
                                  (e.g., 'Welcome', 'Success')
    --false-keywords             Keywords to search for in the false condition response
                                  (e.g., 'Error', 'Invalid')
    --sleep-only                 Use only sleep-based detection methods
    --force                      Skip the injectability check and force a detection method 
                                  (status, content, keyword, or sleep)
    -o, --output-file            Specify a file to output the extracted data

Examples:
    python blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'"
    python blindbrute.py -u "http://example.com/login" -ih Cookie "SESSION=abc123" -t users -c password -w "username='admin'"
    python blindbrute.py -u "http://example.com/login" -f request.txt -t users -c password -w "username='admin'" --binary-attack
    python blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'" --force status
```

## Key Features and Options

### 1. **Injectable and Static Headers**
Specify headers that will be used for the SQL injection payloads (`--injectable-headers`) and static headers that remain constant (`--static-headers`).

### 2. **Customizable Requests**
Provide data in the body of the request for POST requests (`--data`) or use raw HTTP request templates (`--file`) for highly customizable request payloads.

### 3. **Threading for Performance**
Set the threading level with the `--level` flag, ranging from 1 to 5. A higher level increases the number of concurrent workers, improving extraction speed, especially when dealing with large datasets.

### 4. **Binary ASCII Extraction**
Use binary search (`--binary-attack`) to extract ASCII values more efficiently, reducing the number of requests for each character.

### 5. **Dictionary-Based Extraction**
Use a wordlist file (`--dictionary-attack`) to attempt to match entries during extraction, with a fallback to character-based extraction if needed.

### 6. **Sleep-Based Detection**
Use sleep-based SQL injection to detect vulnerabilities and extract data by introducing time delays (`--sleep-only`).

### 7. **Force Detection Method**
Skip the injectability check and force the script to use a specific detection method (`--force`), choosing from status code, content length, keyword-based, or sleep-based detection.

### 8. **Output to File**
Save the extracted data directly to a file using the `--output-file` flag.

## Threading and Performance

The `--level` flag allows you to adjust the threading level (1-5). The number of concurrent threads is determined by the number of CPU cores multiplied by the threading level. Higher levels increase performance but may be limited by your system's I/O capacity.

```bash
--level 1  # Least threads, suitable for low-performance systems
--level 5  # Maximum threading, for fast extraction
```

## License

BlindBrute is released under the MIT License. See LICENSE for more information.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests for any improvements, bug fixes, or new features.

## Disclaimer
This tool is intended for educational purposes and authorized testing only. Do not use this tool on systems without proper authorization. The author is not responsible for any misuse or damage caused by this tool.
