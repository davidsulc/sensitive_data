# Data Leak Prevention

By "data leak", we mean the unintended exposure of sensitive data outside of
its intended environment. How can this happen in Elixir and the BEAM? We'll
look into the various sensitive data leak, how these can be mitigated, and
how `SensitiveData` helps prevent data leaks.

Throughout these examples, we'll use `secret` as a variable whose value we
consider sensitive and therefore don't want to leak. This could be
database credentials, a credit card number, a private cryptography key,
or anything else you really wouldn't want any unauthorized person to be
able to see.

```elixir
secret = "SOME SECRET"
```

But before we get into the thick of things, credit where it's due: the
knowledge distilled here comes in large
part from the work by the [Erlang Ecosystem Foundation](https://erlef.org/)'s
[Security Working Group](https://erlef.org/wg/security), most notably their
article on
[protecting sensitive data](https://erlef.github.io/security-wg/secure_coding_and_deployment_hardening/sensitive_data.html).
Please refer to the latter for coverage of additional techniques you should be
using to protect sensitive data which are beyond the responsibility
of `SensitiveData`'s scope.

## Exceptions and Stack Traces

First, let's define a function that will enable us to see what data
exceptions and stack traces actually contain:

```elixir
defmodule Demo do
    def some_function(arg), do: Map.get(arg, :some_key)

    def inspect_and_reraise(fun) do
        try do
            fun.()
        rescue
            e ->
                IO.inspect(e, label: :exception)
                IO.inspect(__STACKTRACE__, label: :stacktrace)
                reraise e, __STACKTRACE__
        end
    end
end
```

The `some_function/1` function expects a map: what happens if we
inadvertently call it with a different data type?

```elixir
Demo.inspect_and_reraise(fn -> Demo.some_function(secret) end)
```

We're greeted with

```sh
** (BadMapError) expected a map, got: "SOME SECRET"
    (elixir 1.15.4) lib/map.ex:535: Map.get("SOME SECRET", :some_key, nil)
    iex:4: (file)
    iex:4: (file)
```

Oops, our secret is now exposed to stderr, but also in any error tracking tools
we may be using. And as you can see in the console, the sensitive data leaks
from both the exceptions, as well as the stack trace:

```sh
exception: %BadMapError{term: "SOME SECRET"}
stacktrace: [
  {Map, :get, ["SOME SECRET", :some_key, nil],
   [file: ~c"lib/map.ex", line: 535]},
  {:elixir_eval, :__FILE__, 1, [file: ~c"iex", line: 4]},
  {:elixir, :"-eval_external_handler/1-fun-2-", 4,
   [file: ~c"src/elixir.erl", line: 376]},
  {Util, :inspect_and_reraise, 1, [file: ~c"iex", line: 4]},
  {:elixir, :"-eval_external_handler/1-fun-2-", 4,
   [file: ~c"src/elixir.erl", line: 376]},
  {:erl_eval, :do_apply, 7, [file: ~c"erl_eval.erl", line: 750]},
  {:elixir, :eval_forms, 4, [file: ~c"src/elixir.erl", line: 361]},
  {Module.ParallelChecker, :verify, 1,
   [file: ~c"lib/module/parallel_checker.ex", line: 112]}
]
```

So function calls that deal with sensitive data need to be wrapped in a
`try`/`rescue` block so that sensitive arguments can be pruned from the
stack trace, and they must also ensure that sensitive data is removed
from exception structs.

`SensitiveData.execute/1` will do that for you:

```sh
exception: %BadMapError{term: SensitiveData.Redacted}
stacktrace: [
  {Map, :get, 3, [file: ~c"lib/map.ex", line: 535]},
  {:elixir_eval, :__FILE__, 1, [file: ~c"iex", line: 5]},
  {:elixir_eval, :__FILE__, 1, [file: ~c"iex", line: 4]},
  {:elixir, :"-eval_external_handler/1-fun-2-", 4,
   [file: ~c"src/elixir.erl", line: 376]},
  {SensitiveData, :execute, 1, [file: ~c"lib/sensitive_data.ex", line: 22]},
  {:elixir, :"-eval_external_handler/1-fun-2-", 4,
   [file: ~c"src/elixir.erl", line: 376]},
  {Demo, :inspect_and_reraise, 1, [file: ~c"iex", line: 7]},
  {:elixir, :"-eval_external_handler/1-fun-2-", 4,
   [file: ~c"src/elixir.erl", line: 376]}
]
** (BadMapError) expected a map, got: SensitiveData.Redacted
    (elixir 1.15.4) lib/map.ex:535: Map.get/3
    iex:5: (file)
    iex:4: (file)
    iex:3: (file)
```

## State and Crashdumps

Keep in mind that these examples will use a `GenServer` as an example, but any
state-holding process is vulnerable: the same leakage risks exist in `Agent`,
[`:gen_event`](https://www.erlang.org/doc/man/gen_event),
[`:gen_statem`](https://www.erlang.org/doc/man/gen_statem), and so on.

To illustrate how sensitive data can leak from processes, let's use the
following `GenServer` as an example.

```elixir
defmodule Gen do
  use GenServer

  def init(arg) do
    {:ok, arg}
  end
end
```

```
secret = "SOME SECRET"

{:ok, pid} = GenServer.start_link(Gen, secret)
# {:ok, #PID<0.116.0>}

:observer.start()
```

Head to the "Processes" tab, and sort them descending by Pid via a click on that
column's header. Locate the pid for our GenServer (`<0.116.0>` in our example),
right-click on that row and select "Process info for <your pid>".

Within the newly opened window for that specific process, head over to the
"State" column: the row with label "State" will be proudly displaying our
secret plain as day for all to admire.

Naturally, there's an equivalent means to get this directly:

```
:sys.get_status(pid)

# {:status, #PID<0.116.0>, {:module, :gen_server},
#  [
#    [
#      "$initial_call": {Gen, :init, 1},
#      "$ancestors": [#PID<0.110.0>, #PID<0.102.0>]
#    ],
#    :running,
#    #PID<0.110.0>,
#    [],
#    [
#      header: ~c"Status for generic server <0.116.0>",
#      data: [
#        {~c"Status", :running},
#        {~c"Parent", #PID<0.110.0>},
#        {~c"Logged events", []}
#      ],
#      data: [{~c"State", "SOME SECRET"}]
#    ]
#  ]}
```

That's one way sensitive data could reach unworthy eyes, but we're not quite
done ruining our own day yet. "Let it crash" is a beautiful philosophy, but
what happens if there's an unrecoverable crash of the BEAM itself? Let's
find out.

We can crash it ourselves (note the argument is a charlist and *not* an Elixir)
string:

```
:erlang.halt('some unrecoverable error')
```

This will crash the BEAM and write a crash dump file (typically to
"erl_crash.dump"). Let us know open it up and sift through it:

```
:crashdump_viewer.start()
```

Select the file, and feel free to click "yes" when asked if you want to proceed
(in case of an actual crash you're investigating, make a copy of the crash
dump first for safekeeping).

In the Crashdump Viewer, go to the processes tab, and locate the row for the
GenServer's pid (similarly to the Observer case above), right-click and select
"properties for <pid>".

In the newly opened window, head over to the "Stack Dump" tab and browse the
"Term" column: you'll see one starting with `<<"SOME_SECRE"`. Click on it to
view and you'll once again see the sensitive data exposed.