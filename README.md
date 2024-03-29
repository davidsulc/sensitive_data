# SensitiveData

A library for manipulating sensitive/private/confidential data and preventing
data leaks.

The [Data Leak Prevention](pages/data_leak_prevention.md) page exposes the problem
and how this library proposes to address it.

For a quick overview, take a look at the [Getting Started](pages/getting_started.md)
and [Cheatsheet](pages/cheatsheet.cheatmd) pages.

## Installation

The package can be installed by adding `sensitive_data` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:sensitive_data, "~> 0.1.0"}
  ]
end
```

Documentation can be found at <https://hexdocs.pm/sensitive_data>, or
generated locally with [ExDoc](https://github.com/elixir-lang/ex_doc).

## License

Copyright 2024 David Sulc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License [here](LICENSE.txt) or at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
