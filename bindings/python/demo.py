#!/usr/bin/env python3

import os
import pesieve

# set absolute path to the directory with pe-sieve32.dll/pe-sieve64.dll (if different than a directory with pesieve.py)
#os.environ['PESIEVE_DIR'] = os.path.abspath(os.getcwd())

# prepare parameters
params = pesieve.t_params()
params.pid = os.getpid()
params.dotnet_policy = pesieve.t_dotnet_policy.PE_DNET_SKIP_MAPPING
params.imprec_mode = pesieve.t_imprec_mode.PE_IMPREC_AUTO
params.quiet = False
params.out_filter = pesieve.t_output_filter.OUT_FULL
params.no_hooks = False
params.shellcode = pesieve.t_shellc_mode.SHELLC_PATTERNS
params.obfuscated = pesieve.t_obfusc_mode.OBFUSC_NONE
params.threads = True
params.iat = pesieve.t_iat_scan_mode.PE_IATS_CLEAN_SYS_FILTERED
params.data = pesieve.t_data_scan_mode.PE_DATA_SCAN_NO_DEP
params.minidump = False
params.dump_mode = pesieve.t_dump_mode.PE_DUMP_AUTO
params.json_output = True
params.make_reflection = False
params.use_cache = False
params.json_lvl = pesieve.t_json_level.JSON_BASIC
params.output_dir = b"/path/to/output/dir"
params.modules_ignored = pesieve.PARAM_STRING(length=10, buffer=b'ignored1;ignored2')

# run the function
json_max_size = 2000
(report, json, out_size) = pesieve.PESieve_scan_ex(params, pesieve.t_report_type.REPORT_ALL, json_max_size)

# print the report
print("PID: %d" % report.pid)
print("Scanned: %d" % report.scanned)
print("suspicious: %d" % report.suspicious)
print("JSON: %s" % json)
print("out_size: %d" % out_size)
