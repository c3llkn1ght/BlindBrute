# BlindBrute - Blind SQL Injection Brute Forcer

BlindBrute is a highly customizable Python tool designed for blind SQL injection attacks. It supports multiple detection methods, including status codes, content length, keyword-based comparison, and sleep-based SQL injection techniques. It also allows for flexible payload injection using headers, request data, and raw HTTP request templates, making it adaptable to a wide range of scenarios. Data extraction can be optimized in a variety of ways depending on user input. 

## Features
 - **Injection Detection:** Automatically checks if the target field is injectable and determines the best detection method (status code, content length, keywords, or sleep-based).
 - **Column Count Detection:** Determines the number of columns in the target table to craft proper SQL injection payloads.
 - **Database Type Detection:** Identifies the type of database (e.g., MySQL, PostgreSQL, Oracle) to tailor the injection techniques accordingly.
 - **Data Length Discovery:** Discovers the length of the data to optimize the extraction process.
 - **Data Extraction Methods:**
    - **Character-by-Character Extraction:** Extracts data one character at a time.
    - **Binary Search Extraction:** Uses a binary search algorithm to optimize character extraction.
    - **Dictionary Attack:** Uses a provided wordlist to speed up the extraction process.
    - **Custom N-Gram Support:** Generate and use custom n-grams from sample text to prioritize character extraction, improving efficiency.
 - **Threading Support:** Utilizes multithreading to speed up the extraction process.
 - **Customizable Payloads:** Supports injectable headers, request data, and custom request files with placeholders for injections.
 - **Supports HTTP Methods:** GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.

## Requirements

Pyhton 3.6 or higher
requests 2.25.1 or higher

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
    -ih, --injectable-headers    Injectable headers as key-value pairs (e.g., -ih Referer http://example.com)
    -sh, --static-headers        Static headers as key-value pairs that do not contain payloads (e.g., -sh Session_ID abcdefg12345)
    -d, --data                   Specify data to be sent in the request body. Changes request type to POST.
    -f, --file                   File containing the HTTP request with 'INJECT' placeholder for payloads
    -m, --max-length             Maximum length of the data that the script will look for (default: 1000)
    -ba, --binary-attack         Use binary search for ASCII extraction
    -da, --dictionary-attack     Path to a wordlist file for dictionary-based extraction
    -o, --output-file            Specify a file to output the extracted data
    --level                      Specify the threading level (1-5, default: 2)
    --delay                      Delay in seconds between requests to bypass rate limiting
    --timeout                    Timeout for each request in seconds (default: 10)
    --verbose                    Enable verbose output for debugging
    --true-keywords              Keywords to search for in the true condition response (e.g., 'Welcome', 'Success')
    --false-keywords             Keywords to search for in the false condition response (e.g., 'Error', 'Invalid')
    --sleep-only                 Use only sleep-based detection methods
    --force                      Skip the injectability check and force a detection method (status, content, keyword, or sleep)


Examples:
    python blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'"
    python blindbrute.py -u "http://example.com/login"  -t users -c password -w "username='admin' -ih Cookie 'SESSION=abc123'"
    python blindbrute.py -u "http://example.com/login" -f request.txt -t users -c password -w "username='admin'" --binary-attack
    python blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'" --force status --dictionary-attack --level 5
```

## License

BlindBrute is released under the MIT License. See LICENSE for more information.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests for any improvements, bug fixes, or new features.

## Disclaimer
This tool is intended for educational purposes and authorized testing only. Do not use this tool on systems without proper authorization. The author is not responsible for any misuse or damage caused by this tool.
