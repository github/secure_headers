# Feature Requests

## Adding a new header

Generally, adding a new header is always OK. 

* Is the header supported by any user agent? If so, which?
* What does it do?
* What are the valid values for the header?
* Where does the specification live?

## Adding a new CSP directive

* Is the directive supported by any user agent? If so, which?
* What does it do?
* What are the valid values for the directive?

---

# Bugs

Console errors and deprecation warnings are considered bugs that should be addressed with more precise UA sniffing. Bugs caused by incorrect or invalid UA sniffing are also bugs.

### Expected outcome

Describe what you expected to happen 

1. I configure CSP to do X
1. When I inspect the response headers, the CSP should have included X

### Actual outcome

1. The generated policy did not include X

### Config

Please provide the configuration (`SecureHeaders::Configuration.default`) you are using including any overrides (`SecureHeaders::Configuration.override`).

### Generated headers

Provide a sample response containing the headers
