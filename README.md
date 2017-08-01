# NoirSocks Core

Core library of NoirSocks, an extensible and cross-platform socks proxy framework based on boost::asio.
It's a C++ library that can help you easily start a NoirSocks service.

## How to compile

### Linux/MacOSX

Make sure you have boost & openssl installed (both header file and library), then just type:

    # default CXX is clang++
    $ make CXX=g++

Everything should be fine.

### Windows

Also make sure that boost & openssl is installed.
Then just put everything into your VisualStudio project and click Compile button.

## How to use

It's very easy to use NoirSocks Core :

    #include <NoirSocksCore.h> //The only one header file needed.
    // ...
    NoirSocks::GlobalConfig conf; //core config
    // Fill conf ...
    // Start NoirSocks, it will block program execution until Stop() is called or the process is killed.
    NoirSocks::GetServerInstance()->Run(conf);

See [NoirSocks Cli](https://github.com/noirsocks/noirsocks-cli) for an example.
