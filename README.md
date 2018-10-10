<img src="./logo/PE-SIEVE.png" alt="PE-sieve" width=200>

[![Build status](https://ci.appveyor.com/api/projects/status/crlo8iyvi4bm80yp?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-sieve)
[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Twitter URL](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https://github.com/hasherezade/pe-sieve&text=%23PEsieve%3A+an+open-source+process+scanner%2C+detecting+and+dumping+malicious+implants:%20https://github.com/hasherezade/pe-sieve)

<b>PE-sieve</b> is a light-weight tool that helps to detect malware running on the system, as well as to collect the potentially malicious material for further analysis. Recognizes and dumps variety of implants within the scanned process: replaced/injected PEs, shellcodes, hooks, and other in-memory patches.<br/>
Detects inline hooks, Process Hollowing, Process Doppelgänging, Reflective DLL Injection, etc.

uses library:
https://github.com/hasherezade/libpeconv.git

Clone:
-
Use recursive clone to get the repo together with the submodule:
<pre>
git clone --recursive https://github.com/hasherezade/pe-sieve.git
</pre>

Latest builds*:
-
*those builds are available for testing and they may be ahead of the official [release](https://github.com/hasherezade/pe-sieve/releases):
+ [32-bit](https://goo.gl/PnM3U2)
+ [64-bit](https://goo.gl/scP1Hi)
<hr/>

logo by [Baran Pirinçal](https://github.com/baranpirincal)
