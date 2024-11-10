# BlindBrute - Blind SQL Injection Brute Forcer

BlindBrute is a highly customizable Python tool designed for blind SQL injection attacks. It supports multiple detection methods, including status code, content length, keyword comparison, and time-based. It also allows for flexible payload injection using headers, request data, and raw HTTP request templates, making it adaptable to a wide range of scenarios. Data extraction can be optimized in a variety of ways depending on user input. 

## Features
 - **Injection Detection:** Automatically checks if the target field is injectable and determines the best detection method (status code, content length, keywords, or time-based).
   - **Threshold Types and Tolerance:** Dynamically determines and utilizes content length variances by condition (baseline, true, false, error) to improve accuracy.
 - **Column Detection:** Determines the number of columns in the target table to craft proper SQL injection payloads.
 - **Database Detection:** Identifies the type of database to tailor the injection techniques accordingly.
 - **Data Length Discovery:** Discovers the length of the data to optimize the extraction process.
 - **Data Extraction Methods:**
    - **Character-by-Character Extraction:** Extracts data one character at a time.
    - **Binary Search Extraction:** Uses a binary search algorithm to optimize character extraction.
    - **Dictionary Attack:** Uses a provided wordlist to speed up the extraction process.
    - **Custom N-Gram Support:** Generate and use custom n-grams from sample text to prioritize character extraction, improving efficiency.
 - **Threading Support:** Utilizes multithreading to speed up the extraction process.
 - **Customizable Payloads:** Supports injectable headers, request data, and custom request files with placeholders for injections.
 - **Supported HTTP Methods:** GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.

## Requirements

 - Python 3.6 or higher
 - requests 2.25.1 or higher

Install dependencies using:

```bash
pip install -r requirements.txt
```

## Usage

```bash
    BlindBrute - Blind SQL Injection Brute Forcer

    Usage:
        python blindbrute.py -u <URL> -t <TABLE> -c <COLUMN> -w <WHERE CLAUSE> [options]

    Required Arguments:
        -u, --url                    Target URL
        -t, --table                  Table name from which to extract the data (e.g., users)
        -c, --column                 Column name to extract (e.g., password)
        -w, --where                  WHERE clause (e.g., username='Administrator')

    Optional Arguments:
        -ih, --injectable-headers    Injectable headers as key-value pairs (e.g., -ih Referer http://www.example.com)
        -sh, --static-headers        Static headers as key-value pairs that do not contain payloads
        -d, --data                   Specify data to be sent in the request body. Changes request type to POST. INJECT placeholder will be replaced with the payload.
        -f, --file                   File containing the HTTP request with 'INJECT' placeholder for payloads
        -m, --max-length             Maximum length of the extracted data that the script will check for (default: 1000)
        -o, --output-file            Specify a file to output the extracted data
        -qs, --query-string          Query string to append to the URL for GET requests. INJECT placeholder will be replaced with the payload.
        -ba, --binary-attack         Use binary search for ASCII extraction. HIGHLY recommended if character case matters.
        -da, --dictionary-attack     Path to a wordlist for dictionary-based extraction
        -db, --database              Specify the database type (e.g., MySQL, PostgreSQL)
        --level                      Specify the threading level
        --delay                      Delay in seconds between requests to bypass rate limiting
        --timeout                    Timeout for each request in seconds (default: 10)
        --verbose                    Enable verbose output for debugging
        --keywords                   Keywords to search for in the response text
        --sleep-only                 Use sleep-based detection methods strictly. Accepts whole numbers as sleep times. Sleep time must be >= 1. (default: 10)
        --force                      Force a detection method (status, content, keyword, or sleep)
        --gramify                    Generate n-grams and probabilities from the provided file path
        --top-n                      Number of top results to display and save for n-grams. Less is often more here.
    

    Examples:
        blindbrute.py -u "http://example.com/login" -d "username=sam&password=samspasswordINJECT" -t users -c password -w "username='admin'"
        blindbrute.py -u "http://example.com/login" -ih Cookie "SESSION=abc123" -t users -c password -w "username='admin'"
        blindbrute.py -u "http://example.com/login" -f request.txt -t users -c password -w "username='admin'" --binary-attack
        blindbrute.py -u "http://example.com/login" -t users -c password -w "username='admin'" --force status
```

## License

BlindBrute is released under the MIT License. See LICENSE for more information.

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests for any improvements, bug fixes, or new features.

## Disclaimer
This tool is intended for educational purposes and authorized testing only. Do not use this tool on systems without proper authorization. The author is not responsible for any misuse or damage caused by this tool.
