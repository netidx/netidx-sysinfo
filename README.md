Netidx Sysinfo Publisher
====

Publishes top-like stats for a whole host into a netidx hierarchy.

Not to be confused with [netidx-sysfs](https://github.com/netidx/netidx-sysfs)

Setup
===

To setup `cargo install netidx-sysinfo` and make sure you have a netidx
resolver either on the local machine or somewhere on the network. To run,
either run as a regular user, in which case you won't be able to see
everything, or run as root for full access. E.G.

```
# netidx-sysinfo -a local -b local --netidx-base /local/system/sysinfo
```
