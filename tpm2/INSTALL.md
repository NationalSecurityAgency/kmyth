# Building and Installing Kmyth

----
Table of Contents  

  * [Requirements](#requirements)

  * [Installation](#installation)

    * [Dependencies](#dependencies)

    * [Building](#building)

       * [Building Dependencies](#building-the-dependencies)

       * [Building Kmyth](#building-kmyth)

  * [Emulators](#running-with-tpm-20-emulators)
  
----
## Requirements

* TPM version 2.0.

* TPM must be enabled.

* TPM must be configured (see [Notes](#notes))

----
## Installation

### Dependencies

#### Required for building Kmyth:  

* C Standard Library development libraries and headers
* OpenSSL development libraries and headers
* TPM 2.0 TSS development libraries and headers
* TPM 2.0 Access Broker and Resource Manager development libraries and headers
* C compiler
* Make
* indent (GNU program for formatting C code)
* [libkmip](https://github.com/OpenKMIP/libkmip) (used in `getkey`)

With the exception of [libkmip](https://github.com/OpenKMIP/libkmip)
these dependencies can likely be met using your package
manager. [libkmip](https://github.com/OpenKMIP/libkmip) must be
installed from source.

##### CentOS 8 (Red Hat 8) Commands

```yum install openssl openssl-devel glibc gcc libffi-devel```

```yum install tpm2-abrmd tpm2-tss tpm2-tss-devel tpm2-abrmd-devel```

##### Ubuntu 20.04 Commands

```apt install make indent gcc openssl libssl-dev libffi-dev```

```apt install tss2 libtss2-dev libtss2-tcti-tabrmd-dev tpm2-abrmd```

#### Useful TPM 2.0 utilities (may be required for TPM configuration, etc):

* tpm2-tools (command line tools for TPM 2.0 based on tpm2-tss)

##### CentOS 8 (Red Hat 8) Commands

```yum install tpm2-tools```

##### Ubuntu 20.04 Commands

```apt install tpm2-tools```

### Building

#### Building the Dependencies

First, install as many of the above listed dependencies as you can.

The following instructions will walk you through the build process for the
various Kmyth dependencies, using the IBM TPM 2.0 Emulator in place of a
hardware TPM. This guide builds upward from the bottom-level dependencies,
starting with the ```tpm2-tss``` library, then the ```tpm2-tools``` utility
library, and finally the ```tpm2-abrmd``` broker library. We wrap up by
doing a simple build of the emulator. Note that build steps for later tools
or libraries may require dependencies installed earlier in the sequence.

These build instructions were developed and tested on CentOS 8.

##### Building the tpm2-tss library

1. Clone the ```tpm2-tss``` GitHub repository.

```
$ git clone https://github.com/tpm2-software/tpm2-tss.git
$ cd tpm2-tss
```

2. Install dependencies from the PowerTools repository. Note that if PowerTools is already enabled, you can just run the install.

```
$ sudo dnf --enablerepo=PowerTools
$ sudo dnf install autoconf-archive json-c-devel
```

3. Install the remaining dependencies by using the existing upstream ```tpm2-tss``` package.

```
$ sudo dnf builddep tpm2-tss
$ sudo yum -y install libcurl-devel
```

4. Run the ```bootstrap``` and ```configure``` scripts. Note that you may need to change the ```udevrulesdir``` and ```udevrulesprefix``` configuration values for your system setup.

```
$ ./bootstrap
$ ./configure --with-udevrulesdir=/etc/udev/rules.d --with-udevrulesprefix=80-
```

5. Build and install the ```tpm2-tss``` library.

```
$ make -j$(nproc)
$ sudo make install
```

6. Update the system configuration.

```
$ sudo udevadm control --reload-rules && udevadm trigger
$ sudo ldconfig
```

##### Building the tpm2-tools library

1. Clone the ```tpm2-tools``` GitHub repository.

```
$ git clone https://github.com/tpm2-software/tpm2-tools.git
$ cd tpm2-tools
```

2. Install dependencies by using the existing upsream ```tpm2-tools``` package.

```
$ sudo dnf builddep tpm2-tools
```

3. Install additional dependencies.

```
$ sudo yum -y install automake libtool autoconf autoconf-archive libstdc++-devel gcc pkg-config uriparser-devel libgcrypt-devel dbus-devel glib2-devel libcurl-devel libuuid-devel
```

4. Run the ```bootstrap``` and ```configure``` scripts. You may need to change the ```PKG_CONFIG_PATH``` configuration value for your system.

```
$ ./bootstrap
$ PKG_CONFIG_PATh=/usr/local/lib/pkgconfig ./configure
```

5. Build and install the ```tpm2-tools``` library.

```
$ make -j$(nproc)
$ sudo make install
```

6. Update the system configuration.

```
$ sudo ldconfig
```

##### Building the tpm2-abrmd library

1. Clone the ```tpm2-abrmd``` GitHub repository.

```
$ git clone https://github.com/tpm2-software/tpm2-abrmd.git
$ cd tpm2-abrmd
```

2. Install dependencies. 

```
$ sudo yum -y install glib2-devel
```

3. Run the ```bootstrap``` and ```configure``` scripts. You may need to change the ```PKG_CONFIG_PATH``` configuration value for your system.

```
$ ./bootstrap
$ PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure
```

4. Build and install the ```tpm2-abrmd``` library.

```
$ make
$ sudo make install
```

5. Update the system configuration. 

```
$ sudo ldconfig
```

##### Building the IBM TPM 2.0 Emulator

1. Download the emulator package from SourceForge: ```https://sourceforge.net/projects/ibmswtpm2/```

2. Unpack the emulator package. Note the package name may vary slightly depending on when you download it.

```
$ mkdir ibm-tpm2-emulator
$ mv ~/Downloads/ibmtpm1628.tar.gz ibm-tmp2-emulator/.
$ cd ibm-tpm2-emulator
$ tar -xvf ibmtpm1628.tar.gz
```

3. Build the emulator.

```
$ cd src
$ make
```

4. The emulator executable can be found at: ```./src/tpm_server```

##### Building Kmyth

Once the dependencies are installed:

1. Download the code

2. Build and install the kmyth logger
  * In the `kmyth_log` directory run *make* and *make install*

3. The documentation is built using *make doc*. The doxygen generated
   documentation is put in ./doc.

4. In the `tpm2.0` directory run *make* or  *make all* to create:
  * ./bin/kmyth-seal
  * ./bin/kmyth-unseal
  * ./bin/kmyth-getkey

5. The existing build (executables, object files, and documentation) can be
   cleared away to support a fresh build by using *make clean*.


### Running with TPM 2.0 Emulators

Kmyth should function using any TPM 2.0 emulators, however it does
not provide any security benefit and should only be done for testing
purposes.

#### IBM Emulator

* [IBM's TPM 2.0
  emulator](https://sourceforge.net/projects/ibmswtpm2/) can be used
  with Kmyth for testing purposes. If you want to use this emulator there are 2 steps after it is built.
  1. Run the simulator executible.
  2. As the `tss` user execute `tpm2-abrmd --tcti=mssim`


#### Microsoft Simulator

We have not tried this simulator, so if you have please let us know!
