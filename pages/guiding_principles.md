# Guiding Principles

Ensuring sensitive data is always handled with the proper care and precautions
tends to be harder than it appears at first glance.

The approach taken by this library is that reducing risks is made easier by
having a small set of simple rules to follow: it makes it easier to write safe
code, and also facilitates reviewing code for implementations which may be
unsafe.

## Keep It Simple

At its heart, `SensitiveData` boils down to 2 guiding principles:

- use `c:SensitiveData.Wrapper.from/2` to get sensitive data into a wrapper:
    sensitive data shouldn't exist outside of `SensitiveData.Wrapper` wrappers
- use `c:SensitiveData.Wrapper.map/3` and `c:SensitiveData.Wrapper.exec/3` to
    interact with wrapped sensitive data, so it's protected from inadvertent
    leaks from stack traces, crash dumps, and similar

## Default Favor Safety

This library seeks to encourage safer generally-suitable coding practices by
making developers opt-in to features that could leak sensitive data through
inadvertence.

## Closing Thoughts

Using this library in a project does by no means signify that sensitive data
won't leak, nor does it mean developers no longer need to think critically about
data handling: there may be [additional mitigations](./data_leak_prevention.html#additional-mitigations)
you should consider. That said, this library does aim to make the cognitive
load associated with handling sensitive data easier to bear by both the people
writing code and those reviewing it.
