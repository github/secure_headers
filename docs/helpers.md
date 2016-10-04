##### Helpers

**This will not compute dynamic hashes** by design. The output of both helpers will be a plain `script`/`style` tag without modification and the known hashes for a given file will be added to `script-src`/`style-src` when `hashed_javascript_tag` and `hashed_style_tag` are used. You can use `raise_error_on_unrecognized_hash = true` to be extra paranoid that you have precomputed hash values for all of your inline content. By default, this will raise an error in non-production environments.

```erb
<%= hashed_style_tag do %>
body {
  background-color: black;
}
<% end %>

<%= hashed_style_tag do %>
body {
  font-size: 30px;
  font-color: green;
}
<% end %>

<%= hashed_javascript_tag do %>
console.log(1)
<% end %>
```

```
Content-Security-Policy: ...
 script-src 'sha256-yktKiAsZWmc8WpOyhnmhQoDf9G2dAZvuBBC+V0LGQhg=' ... ;
 style-src 'sha256-SLp6LO3rrKDJwsG9uJUxZapb4Wp2Zhj6Bu3l+d9rnAY=' 'sha256-HSGHqlRoKmHAGTAJ2Rq0piXX4CnEbOl1ArNd6ejp2TE=' ...;
```
