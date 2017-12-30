# PE-sieve
[![Build status](https://ci.appveyor.com/api/projects/status/crlo8iyvi4bm80yp?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-sieve)

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

Compiled versions:
-
32bit: https://drive.google.com/uc?export=download&id=1TWRF1BtTEHMdd42CPZXpSmOxO9DFlovL <br/>
64bit: https://drive.google.com/uc?export=download&id=1-LvYrTMJpp4LVo_2fBN5urz2DTezEJvi <br/>
