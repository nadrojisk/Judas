# PythonBackdoor

## Setup

First ensure your box is completely up to date.
The instructions that follow assume you are using a Debian based Linux distribution.
The only system that is known not to work with this framework is macOS as for some reason it does not ship with memory map.

```bash
sudo apt update && sudo apt upgrade -y
```

After updating and upgrading the system install the dependencies needed by Judas.

```bash
pushd
NB_CPU="$(grep -c processor /proc/cpuinfo)"
sudo apt-get install python3-pip git cmake gcc g++ pkg-config libglib2.0-dev libssl-dev -y
cd /tmp
git clone https://github.com/keystone-engine/keystone.git
cd keystone
mkdir build
cd build
sed -i "s/make -j8/make -j${NB_CPU}/g" ../make-share.sh
../make-share.sh
sudo make install
sudo ldconfig
cd ../bindings/python
sudo make install3 # or sudo make install for python2-bindings
popd
```

```bash
pip3 install -r requirements.txt
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
