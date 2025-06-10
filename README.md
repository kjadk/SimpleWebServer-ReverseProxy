# Reverse Proxy Plugin for Simple Web Server

This Node.js plugin extends a "Simple Web Server" to function as a reverse proxy. It enables forwarding requests, basic authentication, rate limiting, and enhances security by adding standard headers.


## Features

* **Reverse Proxy Routing:** Forwards incoming requests to specified backend URLs based on URL paths.
* **Basic Authentication:** Protects proxy routes with username/password authentication.
* **Rate Limiting:** Limits the number of requests from an IP address within a defined time window.
* **Security Headers:** Automatically adds recommended security headers to responses.
* **X-Forwarded-For Handling:** Identifies the original client IP address.
* **Timeout Handling:** Configurable timeout for backend requests.
* **Body Buffering:** Correctly handles request bodies for POST/PUT/PATCH methods.

## Installation

1.  **Download:** download as zip.
2.  **Integrate:** Import folder to simple web server plugins

## Logging

The plugin logs key events to the server's console:

* Details of proxied requests (timestamp, IP, request count, URL).
* Warnings for rate limit excesses.
* Status of periodic IP cleanup (removed IPs, map size).
* General proxying information and errors.


## License

This project is licensed under the MIT License.