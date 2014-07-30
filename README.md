# CVP2 Authentication Test Tool

Brendan Long <b.long@cablelabs.com>

## Setup

If you work at CableLabs, email Brendan Long and request the complete tar file with keys and libraries.

### OpenSSL

First, get a checkout of the CVP2 team's OpenSSL with the cvp2-authentication-test-tool branch:

    git clone https://github.com/cablelabs/openssl.git -b cvp2-authentication-test-tool
    cd openssl
    ./config
    make depend
    make

[Email me](mailto:b.long@cablelabs.com) if that's not enough to build OpenSSL.

Edit catt.conf's `OpenSSL` line to be the full path to apps/openssl (`echo $PWD/apps/openssl` might help).

Note: Don't use this branch for anything besides this tool. We've made a change so that s_client ignores remote certificate failures, and that's usually not what you want.

## Get Keys

To run the tool, you will need to get the following from [DTLA](http://www.dtcp.com/):

  * A production DTCP library.
  * A test DTCP library.
  * A production DTCP certificate and key with the CVP2 bit set.
  * A production DTCP certificate and key without the CVP2 bit set.
  * A test DTCP certificate and key without the CVP2 bit set.

If you have a test DTCP certificate and key with the CVP2 bit set, you can also use that.

Collect all of those files, then edit catt.conf to point to them.

## Run

Clone this repo if you haven't already:

    git clone https://github.com/cablelabs/cvp2-authentication-test-tool.git
    cd cvp2-authentication-test-tool

See the output of `./catt.py -h` for all options. Most likely you will want to run it like:

    ./catt.py --config catt.conf --host [...]

For example, to run against localhost:

    ./catt.py --config catt.conf --host localhost
