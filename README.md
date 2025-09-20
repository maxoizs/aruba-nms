# Aruba Network Management System (NMS)

A Python-based network management system for Aruba network devices.

## Features

- Asynchronous polling of network devices
- GUI interface with sortable columns
- CSV export functionality
- Ability to open custom IP files at runtime

## Installation

### Development Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aruba-nms.git
cd aruba-nms

# Install in development mode
pip install -e .
```

### Regular Installation

```bash
pip install .
```

## Usage

```bash
# Run the GUI application
python -m aruba_nms.nms_gui

# Or use the installed script
aruba-nms-gui
```

## Configuration

You can configure the IP addresses in two ways:

1. Default IP file: Place your IP addresses in the `aruba_nms/data/ip.txt` file, one IP address per line.
2. Custom IP file: Click the "Open IP File" button in the GUI to select any text file containing IP addresses (one per line).

## Dependencies

This project requires:

- Python 3.7+
- tkinter
- ping3
- requests
- pysnmp

## License

[MIT License](LICENSE)
