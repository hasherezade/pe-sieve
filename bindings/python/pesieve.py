#!/usr/bin/env python3

import ctypes
import os

ERROR_SCAN_FAILURE = -1
MAX_PATH =  260

class t_output_filter(ctypes.c_int):
	OUT_FULL = 0
	OUT_NO_DUMPS = 1
	OUT_NO_DIR = 2
	OUT_FILTERS_COUNT = 3

class t_imprec_mode(ctypes.c_int):
	PE_IMPREC_NONE = 0
	PE_IMPREC_AUTO = 1
	PE_IMPREC_UNERASE = 2
	PE_IMPREC_REBUILD0 = 3
	PE_IMPREC_REBUILD1 = 4
	PE_IMPREC_REBUILD2 = 5
	PE_IMPREC_MODES_COUNT = 6

class t_dump_mode(ctypes.c_int):
	PE_DUMP_AUTO = 0
	PE_DUMP_VIRTUAL = 1
	PE_DUMP_UNMAP = 2
	PE_DUMP_REALIGN = 3
	PE_DUMP_MODES_COUNT = 4

class t_iat_scan_mode(ctypes.c_int):
	PE_IATS_NONE = 0
	PE_IATS_CLEAN_SYS_FILTERED = 1
	PE_IATS_ALL_SYS_FILTERED = 2
	PE_IATS_UNFILTERED = 3
	PE_IATS_MODES_COUNT = 4

class t_dotnet_policy(ctypes.c_int):
	PE_DNET_NONE = 0
	PE_DNET_SKIP_MAPPING = 1
	PE_DNET_SKIP_SHC = 2
	PE_DNET_SKIP_HOOKS = 3
	PE_DNET_SKIP_ALL = 4
	PE_DNET_COUNT = 5

class t_data_scan_mode(ctypes.c_int):
	PE_DATA_NO_SCAN = 0
	PE_DATA_SCAN_DOTNET = 1
	PE_DATA_SCAN_NO_DEP = 2
	PE_DATA_SCAN_ALWAYS = 3
	PE_DATA_SCAN_INACCESSIBLE = 4
	PE_DATA_SCAN_INACCESSIBLE_ONLY = 5
	PE_DATA_COUNT = 6

class t_json_level(ctypes.c_int):
	JSON_BASIC = 0
	JSON_DETAILS = 1
	JSON_DETAILS2 = 2
	JSON_LVL_COUNT = 3

class t_report_type(ctypes.c_int):
	REPORT_NONE = 0
	REPORT_SCANNED = 1
	REPORT_DUMPED = 2
	REPORT_ALL = 3

class PARAM_STRING(ctypes.Structure):
	_fields_ = [
		('length', ctypes.c_ulong),
		('buffer', ctypes.c_char_p)
	]

class t_params(ctypes.Structure):
	_fields_ = [
		('pid', ctypes.c_ulong),
		('dotnet_policy', t_dotnet_policy),
		('imprec_mode', t_imprec_mode),
		('quiet', ctypes.c_bool),
		('out_filter', t_output_filter),
		('no_hooks', ctypes.c_bool),
		('shellcode', ctypes.c_bool),
		('threads', ctypes.c_bool),
		('iat', t_iat_scan_mode),
		('data', t_data_scan_mode),
		('minidump', ctypes.c_bool),
		('dump_mode', t_dump_mode),
		('json_output', ctypes.c_bool),
		('make_reflection', ctypes.c_bool),
		('use_cache', ctypes.c_bool),
		('json_lvl', t_json_level),
		('output_dir', ctypes.c_char * (MAX_PATH + 1)),
		('modules_ignored', PARAM_STRING)
	]

class t_report(ctypes.Structure):
	_fields_ = [
		('pid', ctypes.c_ulong),
		('is_managed', ctypes.c_bool),
		('is_64bit', ctypes.c_bool),
		('is_reflection', ctypes.c_bool),
		('scanned', ctypes.c_ulong),
		('suspicious', ctypes.c_ulong),
		('replaced', ctypes.c_ulong),
		('hdr_mod', ctypes.c_ulong),
		('unreachable_file', ctypes.c_ulong),
		('patched', ctypes.c_ulong),
		('iat_hooked', ctypes.c_ulong),
		('implanted', ctypes.c_ulong),
		('implanted_pe', ctypes.c_ulong),
		('implanted_shc', ctypes.c_ulong),
		('other', ctypes.c_ulong),
		('skipped', ctypes.c_ulong),
		('errors', ctypes.c_ulong)
	]

lib = None

def init():
	global lib
	ptr_size = ctypes.sizeof(ctypes.c_voidp)
	if ptr_size == 4:
		pesieve_dll = "pe-sieve32.dll"
	else:
		pesieve_dll = "pe-sieve64.dll"

	if 'PESIEVE_DIR' in os.environ:
		pesieve_dir = os.environ.get('PESIEVE_DIR')
	else:
		pesieve_dir = os.path.abspath(os.getcwd())
	pesieve_path = pesieve_dir + os.path.sep + pesieve_dll
	lib = ctypes.cdll.LoadLibrary(pesieve_path)

def PESieve_help():
	if not lib:
		init()
	lib.PESieve_help()

def PESieve_scan(params: t_params) -> t_report:
	if not lib:
		init()
	if (not isinstance(params, t_params)):
		raise TypeError

	params_size = ctypes.sizeof(t_params)
	pp = ctypes.create_string_buffer(bytes(params), params_size)
	pr = ctypes.create_string_buffer(ctypes.sizeof(t_report))
	lib.PESieve_scan(pr, pp)
	report = t_report.from_buffer(pr)
	return report

def PESieve_scan_ex(params: t_params, rtype: t_report_type, buf_size: int) -> (t_report, str, int):
	if not lib:
		init()
	if (not isinstance(params, t_params)):
		raise TypeError

	pp = ctypes.create_string_buffer(bytes(params), ctypes.sizeof(t_params))
	pr = ctypes.create_string_buffer(ctypes.sizeof(t_report))
	out_size = ctypes.c_ulong(0)
	json_buf = ctypes.create_string_buffer(buf_size)
	lib.PESieve_scan_ex(pr, pp, rtype, json_buf, buf_size, ctypes.byref(out_size))
	report = t_report.from_buffer(pr)
	if (out_size.value):
		json_str = json_buf.value.decode('UTF-8')
	else:
		json_str = ""
	return (report, json_str, out_size.value)
