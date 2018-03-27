# PE-sieve
[![Build status](https://ci.appveyor.com/api/projects/status/crlo8iyvi4bm80yp?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-sieve)
[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

PE-sieve scans a given process, searching for the modules containing in-memory code modifications. When found, it dumps the modified PE.<br/>
Detects inline hooks, hollowed processes etc.

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
