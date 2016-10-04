#### Hash

`script`/`style-src` hashes can be used to whitelist inline content that is static. This has the benefit of allowing inline content without opening up the possibility of dynamic javascript like you would with a `nonce`.

You can add hash sources directly to your policy :

```ruby
::SecureHeaders::Configuration.default do |config|
   config.csp = {
     default_src: %w('self')

     # this is a made up value but browsers will show the expected hash in the console.
     script_src: %w(sha256-123456)
   }
 end
 ```

 You can also use the automated inline script detection/collection/computation of hash source values in your app.

 ```bash
 rake secure_headers:generate_hashes
 ```

 This will generate a file (`config/config/secure_headers_generated_hashes.yml` by default, you can override by setting `ENV["secure_headers_generated_hashes_file"]`) containing a mapping of file names with the array of hash values found on that page. When ActionView renders a given file, we check if there are any known hashes for that given file. If so, they are added as values to the header.

```yaml
---
scripts:
  app/views/asdfs/index.html.erb:
  - "'sha256-yktKiAsZWmc8WpOyhnmhQoDf9G2dAZvuBBC+V0LGQhg='"
styles:
  app/views/asdfs/index.html.erb:
  - "'sha256-SLp6LO3rrKDJwsG9uJUxZapb4Wp2Zhj6Bu3l+d9rnAY='"
  - "'sha256-HSGHqlRoKmHAGTAJ2Rq0piXX4CnEbOl1ArNd6ejp2TE='"
```
