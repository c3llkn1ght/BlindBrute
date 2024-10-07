# BlindBrute

**BlindBrute** BlindBrute is a Python tool for performing blind SQL injection attacks using multiple detection methods. It supports status code, content length, keyword-based and sleep-based comparisons to detect injection vulnerabilities and extract data. The tool allows the user to choose various detection techniques for injection, customize payloads, and perform blind SQL data extraction with detailed control over requests, timeouts, and delays.

## Features

- **Injection Detection**: Detect SQL injection vulnerabilities using multiple methods:
  - **Status Code Comparison**: Check for differences in HTTP response status codes between injected and baseline requests.
  - **Content Length Comparison**: Compare the length of HTTP response content to identify changes caused by injection.
  - **Keyword Matching**: Provide custom keywords to search for in the true and false condition responses for more targeted detection.
- **Data Extraction**: Perform blind SQL injection to extract data character by character from vulnerable fields.
- **Customizable Payloads**: Supports custom SQL queries and payloads for different tables, columns, and conditions.
- **Delay Between Requests**: Helps avoid rate-limiting with an optional delay between requests.
- **Request Timeout**: Provides a configurable timeout for requests to prevent the script from hanging on slow servers.
- **Verbose Output**: Detailed logs of each step, including payloads, status codes, content lengths, and detected keywords.
- **File-Based Requests**: Accepts raw HTTP requests from files with placeholders for injection.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/c3llkn1ght/blindbrute.git
   cd blindbrute
   ```
   
2. Install the required dependencies:
   ```bash
   pip install requirements.txt

## Usage
The tool can be run with various parameters to perform injection detection and data extraction. Below are some examples of how to use BlindBrute.

#### Basic Injection Detection (Status Code or Content Length)
```bash
python blindbrute.py -u http://target.com -cn session_id -cv abc123 -t Users -c Password -w "Username = 'Administrator'"
```
This will detect whether the specified field is injectable by comparing either the status code or the content length of the responses.

#### Keyword-Based Detection
```bash
python blindbrute.py -u http://target.com --true-keywords "Welcome" "Logged in" --false-keywords "Error" "Invalid" -cn session_id -cv abc123 -t Users -c Password -w "Username = 'Administrator'"
```
In this example, BlindBrute will use keyword matching to detect injection vulnerabilities based on the presence of specific keywords in the response. If the keywords for the true and false conditions are found, the tool will assume the field is injectable.

#### File-Based Requests
```bash
python blindbrute.py -u http://target.com -f request.txt -t Users -c Password -w "Username = 'Administrator'"
```
You can provide a raw HTTP request file where the placeholder INJECT indicates where the SQL injection payload will be inserted. The tool will replace INJECT with the payload during execution.

Available Flags
Flag	Description
**-u, --url**	The target URL to send requests to (required).
**-cn, --cookie-name**	The name of the cookie field for injection (optional).
**-cv, --cookie-value**	The value of the cookie field for injection (optional).
**-t, --table**	The table from which to extract data (for data extraction).
**-c, --column**	The column to extract data from (for data extraction).
**-w, --where**	The WHERE clause for SQL injection (e.g., Username = 'Admin').
**--true-keywords**	Keywords to look for in the true condition response (e.g., Welcome).
**--false-keywords**	Keywords to look for in the false condition response (e.g., Error).
**--delay**	Delay (in seconds) between requests to avoid rate-limiting (default: 0).
**--verbose**	Enable verbose output for debugging and detailed logging.
**-f, --file**	Path to a file containing the raw HTTP request with an INJECT placeholder for SQL payloads.
**--sleep-only**	Use only sleep-based detection methods for time-based SQL injection.
**--timeout**	Timeout for each request in seconds (default: 10).

## How It Works

#### Injection Detection Methods:
BlindBrute allows users to choose from multiple comparison methods to detect SQL injection vulnerabilities:

**Status Code Comparison:** Checks if the server returns different status codes for injected and non-injected requests.
**Content Length Comparison:** Compares the length of the HTTP response content for changes that suggest successful injection.
**Keyword Matching:** The most powerful option, allowing users to specify keywords to search for in the response. This method will override the other two methods if selected.

#### Data Extraction:
Blind SQL injection is performed by testing individual characters in the extracted data. The tool will brute-force the value character by character, checking each response for the success of the injection based on the selected detection method.

## Contributing
Contributions are welcome! Feel free to open issues and submit pull requests.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
This tool is intended for educational purposes and authorized testing only. Do not use this tool on systems without proper authorization. The author is not responsible for any misuse or damage caused by this tool.
