# Getting Started

This short guide will help you get up to speed with using this library. It will
use API credentials and interactation as a guiding example, but the details
don't matter.

For context, the relevant things to know about this example are:

- API username and password are available in [environment variables](https://en.wikipedia.org/wiki/Environment_variable)
    and are considered to be highly sensitive
- API authentication happens via [basich auth](https://en.wikipedia.org/wiki/Basic_access_authentication)
- `fetch_data_from_api` makes a call to the authenticated API, for which it
    requires access credentials already in the basic auth format

## Create a Wrapper Module

First we need to define a wrapper module to hold sensitive data:

```elixir
defmodule MyApp.SecretData do
  use SensitiveData.Wrapper
end
```

This `MyApp.SecretData` module implements the `SensitiveData.Wrapper`
behaviour, so feel free to read more about it in the documentation.

## Wrap Sensitive Data

Let's fetch the sensitive credentials from the environment, and convert them
into a more convenient form:

```elixir
alias MyApp.SecretData

api_credentials =
  SecretData.from(fn ->
    user = System.fetch_env!("API_USER")
    password = System.fetch_env!("API_PASSWORD")
    Base.encode64("#{user}:#{password}")
  end)
```

## Interact with Wrapped Data

With our credentials available in a wrapper, we can now make use of this
sensitive information safely via `c:SensitiveData.Wrapper.exec/3`:

```elixir
alias MyApp.SecretData

{:ok, _api_call_result} =
  SecretData.exec(api_credentials, fn basic_auth ->
    fetch_data_from_api(basic_auth: basic_auth)
  end)
```

This way if there's any issue, we can be sure that no sensitive information
(e.g., API authentication credentials) will leak through stack traces,
crash dumps, runtime state inspection, and so on.

<!-- It will
use a database credentials and interactation as a guiding example, but the
details don't matter: you should be able to follow along even if you've never
used a database (much less `Postgrex`) or even know what a database does. -->

<!-- For context, the relevant things to know about this example are:

- the information in the "DB_URI" [environment variable](https://en.wikipedia.org/wiki/Environment_variable)
    is highly sensitive as it could give access to confidential information
    stored in the database if the value were read
- the connection information is formatted as a [URI](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier),
    but the function to connect to the database requires the configuration to
    be provided as a keyword list: we'll need to parse the URI before we'll
    be able to connect to the database. The actual parsing will be done by
    `parse_postgres_uri` in our example. Just like any function,
    `parse_postgres_uri` can fail and may expose sensitive information (such as
    the database password) in a stack trace.

## Create a Wrapper Module

First we need to define a wrapper module to hold sensitive data:

```elixir
defmodule MyApp.SecretData do
  use SensitiveData.Wrapper
end
```

This `MyApp.SecretData` module implements the `SensitiveData.Wrapper`
behaviour, so feel free to read more about it in the documentation.

## Wrap Sensitive Data

```elixir
alias MyApp.SecretData

database_uri = SecretData.from(fn -> System.get_env("DB_URI") end)
```

## Interact with Wrapped Data

```elixir
alias MyApp.SecretData

{:ok, pid} =
  SecretData.exec(database_uri, fn uri ->
    uri
    |> parse_postgres_uri()
    |> Postgrex.start_link()
  end)
``` -->
