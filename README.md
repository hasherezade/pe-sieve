<img src="https://raw.githubusercontent.com/hasherezade/pe-sieve/master/logo/PE-SIEVE.png" alt="PE-sieve" width=200>

[![Build status](https://ci.appveyor.com/api/projects/status/crlo8iyvi4bm80yp?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-sieve)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b75fd4d95bd94629879381241e4a7c02)](https://www.codacy.com/manual/hasherezade/pe-sieve?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=hasherezade/pe-sieve&amp;utm_campaign=Badge_Grade)
[![GitHub release](https://img.shields.io/github/release/hasherezade/pe-sieve.svg)](https://github.com/hasherezade/pe-sieve/releases)
[![Github All Releases](https://img.shields.io/github/downloads/hasherezade/pe-sieve/total.svg)](https://github.com/hasherezade/pe-sieve/releases)
[![Github Latest Release](https://img.shields.io/github/downloads/hasherezade/pe-sieve/latest/total.svg)](https://github.com/hasherezade/pe-sieve/releases)

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Platform Badge](https://img.shields.io/badge/Windows-0078D6?logo=windows)](https://github.com/hasherezade/pe-sieve)
[![Discussions](https://img.shields.io/badge/Ask%20me-anything-1abc9c.svg)](https://github.com/hasherezade/pe-sieve/discussions)

[![Twitter URL](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https://github.com/hasherezade/pe-sieve&text=%23PEsieve%3A+an+open-source+process+scanner%2C+detecting+and+dumping+malicious+implants:%20https://github.com/hasherezade/pe-sieve)

❓ [FAQ - Frequently Asked Questions](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ)

📖 [Read Wiki](https://github.com/hasherezade/pe-sieve/wiki)

<b>PE-sieve</b> is a tool that helps to detect malware running on the system, as well as to collect the potentially malicious material for further analysis. Recognizes and dumps variety of implants within the scanned process: replaced/injected PEs, shellcodes, hooks, and other in-memory patches.<br/>
Detects inline hooks, Process Hollowing, Process Doppelgänging, Reflective DLL Injection, etc.

PE-sieve is meant to be a **light-weight engine** dedicated to scan **a single process** at the time. It can be built as an EXE or as a DLL. The DLL version exposes a simple API and can be easily integrated with other applications.

If instead of scanning a particular process you want to scan your **full system** with PE-sieve, you can use [HollowsHunter](https://github.com/hasherezade/hollows_hunter). It contains PE-sieve (a DLL version), but offers also some additional features and filters on the top of this base.

📦 Uses library: [libPEConv](https://github.com/hasherezade/libpeconv.git)

Clone
-
Use **recursive clone** to get the repo together with the submodule:

```console
git clone --recursive https://github.com/hasherezade/pe-sieve.git
```

Builds
-
Download the latest [release](https://github.com/hasherezade/pe-sieve/releases), or [read more](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ#how-to-get-it).

<hr/>

logo by [Baran Pirinçal](https://github.com/baranpirincal)
