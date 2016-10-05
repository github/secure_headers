## HTTP Public Key Pins

Be aware that pinning error reporting is governed by the same rules as everything else. If you have a pinning failure that tries to report back to the same origin, by definition this will not work.

```ruby
config.hpkp = {
  max_age: 60.days.to_i,    # max_age is a required parameter
  include_subdomains: true, # whether or not to apply pins to subdomains
  # Per the spec, SHA256 hashes are the only currently supported format.
  pins: [
    {sha256: 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'},
    {sha256: '73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'}
  ],
  report_only: true,        # defaults to false (report-only mode)
  report_uri: 'https://report-uri.io/example-hpkp'
}
```
