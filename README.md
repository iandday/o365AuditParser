# o365AuditParser

# Office 365 Audit Log Parser

This script will process [Microsoft Office365 Protection Center Audit Logs](https://docs.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log) into a useable form to allow efficient fitlering and pivoting off events of interest.

This script was written as the final project for [Champlain's Scripting for Digital Forensics course (DFS-510-85)](https://www.champlain.edu/online/masters-degrees/ms-digital-forensics/curriculum)

## Usage

```bash
usage: o365AuditParser.py [-h] [-o OUTPUT] [-p PREFIX] [-f {csv,json}]
                          (-w | -c) [-v] [--version]
                          input

o365 Audit Log Extractor

positional arguments:
  input                 File/Directory to process

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output directory, defaults to current directory
  -p PREFIX, --prefix PREFIX
                        Prefix for output files, defaults to o365AuditLog
  -f {csv,json}, --format {csv,json}
                        Output file format, defaults to csv
  -w, --workload        Generate individual output files per workload
  -c, --combined        Generate one output file
  -v, --verbose         Enable debug logging
  --version             show program's version number and exit
  ```

The script supports processing a single file or a directory of files.  Output can be generated in a single file (`-c` or `--combined`) or separate files (`-w` or `--workload`) per Office365 workload(application) in either JSON (`--format json`) or CSV (`--format csv`) format. Redacted sample input files are available in the examples directory along with output files in all possible formats.