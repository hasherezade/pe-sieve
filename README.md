<img src="./logo/PE-SIEVE_small.png" alt="">

[![Build status](https://ci.appveyor.com/api/projects/status/crlo8iyvi4bm80yp?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-sieve)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b75fd4d95bd94629879381241e4a7c02)](https://app.codacy.com/gh/hasherezade/pe-sieve/dashboard?branch=master)
[![Commit activity](https://img.shields.io/github/commit-activity/m/hasherezade/pe-sieve)](https://github.com/hasherezade/pe-sieve/commits)
[![Last Commit](https://img.shields.io/github/last-commit/hasherezade/pe-sieve/master)](https://github.com/hasherezade/pe-sieve/commits)

[![GitHub release](https://img.shields.io/github/release/hasherezade/pe-sieve.svg)](https://github.com/hasherezade/pe-sieve/releases)
[![GitHub release date](https://img.shields.io/github/release-date/hasherezade/pe-sieve?color=blue)](https://github.com/hasherezade/pe-sieve/releases)
[![Github All Releases](https://img.shields.io/github/downloads/hasherezade/pe-sieve/total.svg)](https://github.com/hasherezade/pe-sieve/releases)
[![Github Latest Release](https://img.shields.io/github/downloads/hasherezade/pe-sieve/latest/total.svg)](https://github.com/hasherezade/pe-sieve/releases)

[![License](https://img.shields.io/badge/License-BSD%202--Clause-blue.svg)](https://github.com/hasherezade/pe-sieve/blob/master/LICENSE)
[![Platform Badge](https://img.shields.io/badge/Windows-0078D6?logo=windows)](https://github.com/hasherezade/pe-sieve)
[![Discussions](https://img.shields.io/badge/Ask%20me-anything-1abc9c.svg)](https://github.com/hasherezade/pe-sieve/discussions)

[![Twitter URL](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https://github.com/hasherezade/pe-sieve&text=%23PEsieve%3A+an+open-source+process+scanner%2C+detecting+and+dumping+malicious+implants:%20https://github.com/hasherezade/pe-sieve)

## Intro

<b>PE-sieve</b> is a tool that helps to detect malware running on the system, as well as to collect the potentially malicious material for further analysis. Recognizes and dumps variety of implants within the scanned process: replaced/injected PEs, shellcodes, hooks, and other in-memory patches.<br/>
Detects inline hooks, Process Hollowing, Process Doppelgänging, Reflective DLL Injection, etc.

PE-sieve is meant to be a **light-weight engine** dedicated to scan **a single process** at the time. It can be built as an EXE or as a DLL. The DLL version exposes [a simple API](https://github.com/hasherezade/pe-sieve/wiki/5.-API) and can be easily integrated with other applications.

📦 Uses library: [libPEConv](https://github.com/hasherezade/libpeconv.git)

## Help

❓ [FAQ - Frequently Asked Questions](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ)

📖 [Read Wiki](https://github.com/hasherezade/pe-sieve/wiki)

🤔 Do you have any question that was not included in the [FAQ](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ)? Join [Discussions](https://github.com/hasherezade/pe-sieve/discussions)!

## PE-sieve tools family

There are few other tools that use PE-sieve as an engine, but focus on some specific usecases. They offer additional features and filters on the top of its base.

📌 [HollowsHunter](https://github.com/hasherezade/hollows_hunter) - if instead of scanning a single process you want to **scan multiple processes at once, or even the full system** with PE-sieve, this is the tool for you

📌 [MalUnpack](https://github.com/hasherezade/mal_unpack) - offers quick **unpacking** of supplied malware sample

## Clone

Use **recursive clone** to get the repo together with the submodule:

```console
git clone --recursive https://github.com/hasherezade/pe-sieve.git
```

## Builds

Download the latest [release](https://github.com/hasherezade/pe-sieve/releases), or [read more](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ#how-to-get-it).

![](https://community.chocolatey.org/favicon.ico) Available also via [Chocolatey](https://community.chocolatey.org/packages/pesieve)

<hr/>

logo by [Baran Pirinçal](https://github.com/baranpirincal)
