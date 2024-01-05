defmodule SensitiveData.IO do
  ############ Code taken from Hex ########################################
  #
  # https://github.com/hexpm/hex/blob/1881f9fe8e0571ba7fdcfc86ecf484913125dc37/lib/mix/tasks/hex.ex#L363
  # Copyright 2015 Six Colors AB
  # Licensed under the Apache License, Version 2.0 (the "License")
  #
  # No significant changes made (only a rename: `password_get` to `gets_sensitive`)
  #
  def gets_sensitive(prompt \\ "") do
    pid = spawn_link(fn -> loop(prompt) end)
    ref = make_ref()
    value = IO.gets(prompt <> " ")

    send(pid, {:done, self(), ref})
    receive do: ({:done, ^pid, ^ref} -> :ok)

    value
    |> to_string()
    |> String.trim()
  end

  defp loop(prompt) do
    receive do
      {:done, parent, ref} ->
        send(parent, {:done, self(), ref})
        IO.write(:standard_error, "\e[2K\r")
    after
      1 ->
        IO.write(:standard_error, "\e[2K\r#{prompt} ")
        loop(prompt)
    end
  end

  #
  ############ End code taken from Hex ########################################
end
