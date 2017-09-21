# F5-BIGIP-Decoder
Detecting and decoding BIG IP cookies in bash

Bash script to print out private IPs, ports and other stuff from F5's BIG IP Loadbalancers -- from not encrypted cookies which is still the default. It detects all cookies, also the AES encrypted ones.

**Usage**

``f5_bigip_decoder.sh <URL>`` or ``f5_bigip_decoder.sh <cookie value>`` or ``f5_bigip_decoder.sh <cookie name=cookie value>``

**Example**

``f5_bigip_decoder.sh TEST`` gives you an idea by running it against a predefined header

**Caveats**

I didn't spend much time to make the code beautiful.
