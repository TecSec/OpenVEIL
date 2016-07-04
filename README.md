# OpenVEIL

OpenVEIL is the foundation of the the applications that make up the VEIL suite of products.  This component has been released to the Open Source community to facilitate the incorporation of VEIL technology into more products.

VEIL is the productization of a revolutionary Key Management system called Constructive Key Management.  This key management system has been vetted and published in the following standards:
* ANSI X9.69
* ANSI X9.73-2010



## Installation

We use an out of source build process.  The project/make files and output
can be found in the build folder that is created by the bootstrap.

### Requirements
- VEIL Cryptographic Library (Contact TecSec, Inc.)
- Windows
  - CMake 3.2+
  - Visual Studio 2013 or Visual Studio 2015.
- Linux
  - CMake 3.2+
  - GCC 4.8.2+
	
### Windows
	
1. Clone the repository
2. Go to the directory of the repository in a command prompt
3. `cd make\windows`
4. Run the following command to bootstrap x86 and x64(Debug and Release)
  - If Visual Studio 2015:
    - `bootstrap_VS2015.cmd`
  - If Visual Studio 2013:
    - `bootstrap_VS2013.cmd`
5. `cd ..\..\Build`
6. Run the following command to build x86 and x64(Debug and Release)
  - If Visual Studio 2015:
    - `buildall-vc14.cmd`
  - If Visual Studio 2013:
    - `buildall-vc12.cmd`
7. After the build is complete there should be a C:\TecSec\OpenVEIL_7-0 directory. Within that
directory there is a folder depending on which version of Visual Studio was used. Within that
directory there is a bin directory that has DLLs and executables for OpenVEIL. Directories
that end in 'd' were built with Debug.

### Linux

TODO: Describe the installation process

## Usage

TODO: Write usage instructions

## Documentation

Documentation is not available yet.  Sorry.

## Contributing

To become a contributor to this project please look at the document called
**Contribution Agreement.pdf**

## License

See **LICENSE.md**
