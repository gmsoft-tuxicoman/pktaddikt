# pktaddikt

**pktaddikt** is an event-driven deep packet inspection (DPI) tool written in Rust.
It reads live network traffic or packet capture files, dissects packets across multiple
protocol layers, and generates structured events and files that can be routed to
a variety of outputs.

## Requirements

- [libpcap](https://www.tcpdump.org/)
```shell
  # Debian / Ubuntu
  sudo apt install libpcap-dev

  # Fedora / RHEL
  sudo dnf install libpcap-devel
```

- [nftables](https://nftables.org/) — required unless built without the `nftables` feature
```shell
  # Debian / Ubuntu
  sudo apt install nftables

  # Fedora / RHEL
  sudo dnf install nftables
```

## Building

```shell
# Standard build (nftables support enabled by default)
cargo build --release

# Without nftables support
cargo build --release --no-default-features
```

## Usage

```shell
pktaddikt [OPTIONS]

Options:
  -c, --config           Path to config file [default: config.yaml]
  -r, --read          Read from a packet capture file
  -i, --interface     Capture from a live network interface
  -h, --help                     Print help
```

Command-line options override their equivalent settings in the config file.

## Configuration

Copy the example config and adjust it to your needs:

```shell
cp config.example.yaml config.yaml
```

See [`config.example.yaml`](config.example.yaml) for the full list of available
inputs, outputs, and options.

## License

MIT — see [LICENSE](LICENSE)
