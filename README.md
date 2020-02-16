# PythonBackdoor

## Setup

```bash
cd src
python3 setup.py develop
```

```bash
pip install -r requirements.txt
```

## Windows

If running this script on Windows ensure you exclude this folder from Windows Defender scans.
If you do not Windows Defender will automatically delete the file produced by the script.
Go to `Windows Defender Security Center`, then `Virus & threat protection settings`, and at the bottom there is `Exclusions`.
Add a new folder and put in the path for this repo.

## Resources

* https://www.microsoft.com/en-us/download/confirmation.aspx?id=53354
* https://captmeelo.com/exploitdev/osceprep/2018/07/16/backdoor101-part1.html
* https://resources.infosecinstitute.com/back-dooring-pe-files-windows/
* https://r0ttenbeef.github.io/backdooring-pe-file/
* https://axcheron.github.io/code-injection-with-python/
* http://yuba.stanford.edu/~casado/pcap/section1.html

## Documentation

* https://docs.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN

## Dependancies

* Disassembler
  * https://github.com/aquynh/capstone
* Assembler
  * https://github.com/keystone-engine/keystone
* PE Parser
  * https://github.com/erocarrera/pefile
