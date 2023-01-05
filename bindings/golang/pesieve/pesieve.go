package pesieve

import (
	"fmt"
	"syscall"
	"unsafe"
	"os"
)

const (
	is64Bit = uint64(^uintptr(0)) == ^uint64(0)
)

var(
	PesieveDir string = os.Getenv("PESIEVE_DIR")
	PesieveFile string

	peSieveDll *syscall.LazyDLL
	_peSieveHelp *syscall.LazyProc
	_peSieveScan *syscall.LazyProc
	_peSieveScanEx *syscall.LazyProc
)

func init() {
	if is64Bit {
		PesieveFile = "pe-sieve64.dll"
	} else {
		PesieveFile = "pe-sieve32.dll"
	}
	if PesieveDir == "" {
		PesieveDir, _ = os.Getwd()
	}
	var pesievePath = PesieveDir + "\\" + PesieveFile
	peSieveDll = syscall.NewLazyDLL(pesievePath)
	_peSieveHelp = peSieveDll.NewProc("PESieve_help")
	_peSieveScan = peSieveDll.NewProc("PESieve_scan")
	_peSieveScanEx = peSieveDll.NewProc("PESieve_scan_ex")
}

const (
	ERROR_SCAN_FAILURE int32 = -1
	MAX_PATH            = 260
)

type t_output_filter uint32

const (
	OUT_FULL          t_output_filter = 0 ///< no filter: dump everything (default)
	OUT_NO_DUMPS      t_output_filter = 1 ///< don't dump the modified PEs, but save the report
	OUT_NO_DIR        t_output_filter = 2 ///< don't dump any files
	OUT_FILTERS_COUNT t_output_filter = 3
)

type t_imprec_mode uint32

const (
	PE_IMPREC_NONE        t_imprec_mode = 0 ///< do not try to recover imports
	PE_IMPREC_AUTO                      = 1 ///< try to autodetect the most suitable mode
	PE_IMPREC_UNERASE                   = 2 ///< recover erased parts of the partialy damaged import table
	PE_IMPREC_REBUILD0                  = 3 ///< build the import table from the scratch, basing on the found IAT(s): use only terminated blocks (restrictive mode)
	PE_IMPREC_REBUILD1                  = 4 ///< build the import table from the scratch, basing on the found IAT(s): use terminated blocks, or blocks with more than 1 thunk
	PE_IMPREC_REBUILD2                  = 5 ///< build the import table from the scratch, basing on the found IAT(s): use all found blocks (aggressive mode)
	PE_IMPREC_MODES_COUNT               = 6
)

type t_dump_mode uint32

const (
	PE_DUMP_AUTO         t_dump_mode = 0 ///< autodetect which dump mode is the most suitable for the given input
	PE_DUMP_VIRTUAL                  = 1 ///< dump as it is in the memory (virtual)
	PE_DUMP_UNMAP                    = 2 ///< convert to the raw format: using raw sections' headers
	PE_DUMP_REALIGN                  = 3 ///< convert to the raw format: by realigning raw sections' headers to be the same as virtual (useful if the PE was unpacked in memory)
	PE_DUMP_MODES_COUNT              = 4
)

type t_iat_scan_mode uint32

const (
	PE_IATS_NONE            t_iat_scan_mode = 0 ///< do not scan IAT
	PE_IATS_CLEAN_SYS_FILTERED              = 1 ///< scan IAT, filter hooks if they lead to unpatched system module
	PE_IATS_ALL_SYS_FILTERED                = 2 ///< scan IAT, filter hooks if they lead to any system module
	PE_IATS_UNFILTERED                      = 3 ///< scan IAT, unfiltered
	PE_IATS_MODES_COUNT                     = 4
)

type t_dotnet_policy uint32

const (
	PE_DNET_NONE            t_dotnet_policy = 0 ///< none: treat managed processes same as native
	PE_DNET_SKIP_MAPPING                    = 1 ///< skip mapping mismatch (in .NET modules only)
	PE_DNET_SKIP_SHC                        = 2 ///< skip shellcodes (in all modules within the managed process)
	PE_DNET_SKIP_HOOKS                      = 3 ///< skip hooked modules (in all modules within the managed process)
	PE_DNET_SKIP_ALL                        = 4 ///< skip all above indicators (mapping, shellcodes, hooks) in modules within the managed process
	PE_DNET_COUNT                           = 5
)

type t_data_scan_mode uint32

const (
	PE_DATA_NO_SCAN        t_data_scan_mode = 0 ///< do not scan non-executable pages
	PE_DATA_SCAN_DOTNET                     = 1 ///< scan data in .NET applications
	PE_DATA_SCAN_NO_DEP                     = 2 ///< scan data if no DEP or in .NET applications
	PE_DATA_SCAN_ALWAYS                     = 3 ///< scan data unconditionally
	PE_DATA_SCAN_INACCESSIBLE               = 4 ///< scan data unconditionally, and inaccessible pages (if running in reflection mode)
	PE_DATA_SCAN_INACCESSIBLE_ONLY          = 5 ///< scan inaccessible pages (if running in reflection mode)
	PE_DATA_COUNT                           = 6
)

type t_json_level uint32

const (
	JSON_BASIC    t_json_level = 0 ///< basic
	JSON_DETAILS               = 1 ///< include the basic list patches in the main JSON report
	JSON_DETAILS2              = 2 ///< include the extended list patches in the main JSON report
	JSON_LVL_COUNT             = 3
)

type t_report_type uint32

const (
	REPORT_NONE      t_report_type = 0 ///< do not output a report
	REPORT_SCANNED                 = 1 ///< output the scan report
	REPORT_DUMPED                  = 2 ///< output the dumps report
	REPORT_ALL                     = 3 ///< output all available reports
)

type PARAM_STRING struct {
	Length  uint32
	Buffer  []byte
}

type t_params struct {
	Pid              uint32          ///< the PID of the process to be scanned
	DotnetPolicy     t_dotnet_policy ///< policy for scanning .NET modules
	ImprecMode       t_imprec_mode   ///< import recovery mode
	Quiet            bool            ///<do not print log on the stdout
	Out_filter       t_output_filter ///< level of details of the created output material
	NoHooks          bool            ///< don't scan for hooks
	Shellcode        bool            ///< detect shellcode implants
	Threads          bool            ///< scan threads
	IAT              t_iat_scan_mode ///< detect IAT hooking
	Data             t_data_scan_mode///< should scan non-executable pages?
	Minidump         bool            ///< make minidump of full process
	DumpMode         t_dump_mode     ///< in which mode the detected PE implants should be dumped
	JsonOutput       bool            ///< display the final summary as the JSON report
	MakeReflection   bool            ///< operate on a process reflection rather than on the live process (this allows i.e. to force-read inaccessible pages)
	UseCache         bool            ///< enable cache for the scanned modules
	JsonLvl          t_json_level    ///< level of the details of the JSON report
	OutputDir        [MAX_PATH + 1]byte ///< the root directory where the output should be saved (default: current directory)
	ModulesIgnored   PARAM_STRING    ///< a list of modules that will not be scanned, separated by PARAM_LIST_SEPARATOR
}
type PEsieveParams t_params

type t_report struct {
	Pid              uint32        ///< pid of the process that was scanned
	IsManaged        bool          ///< is process managed (.NET)
	Is64bit          bool          ///< is process 64 bit
	IsReflection     bool          ///< was the scan performed on process reflection
	Scanned          uint32        ///< number of all scanned modules
	Suspicious       uint32        ///< general summary of suspicious
	Replaced         uint32        ///< PE file replaced in memory (probably hollowed)
	HdrMod           uint32        ///< PE header is modified (but not replaced)
	UnreachableFile  uint32        ///< cannot read the file corresponding to the module in memory
	Patched          uint32        ///< detected modifications in the code
	IATHooked        uint32        ///< detected IAT hooks
	Implanted        uint32        ///< all implants: shellcodes + PEs
	ImplantedPe      uint32        ///< the full PE was probably loaded manually
	ImplantedShc     uint32        ///< implanted shellcodes
	Other            uint32        ///< other indicators
	Skipped          uint32        ///< some of the modules must be skipped (i.e. dotNET managed code have different characteristics and this scan does not apply)
	Errors           uint32        ///< the number of elements that could not be scanned because of errors. If errors == ERROR_SCAN_FAILURE, no scan was performed.
}
type PEsieveReport t_report

func PESieveHelp() {
	_peSieveHelp.Call()
}

// Basic PEsieve scan
func PESieveScan(pp PEsieveParams) PEsieveReport {
	// Perform the scan:)
	pr := PEsieveReport{}
	_, status, out2 := _peSieveScan.Call(
		uintptr(unsafe.Pointer(&pr)), // first pass the return variable
		uintptr(unsafe.Pointer(&pp)), // then pass the typical arguments of the function
	)
	if status != 0 {
		fmt.Println("Error:", out2)
	}
	return pr
}

//Extended PEsieve scan
func PESieveScanEx(pp PEsieveParams, rtype t_report_type, jsonMaxSize uint32) (PEsieveReport, string, uint32){
	// Perform the scan:
	pr := PEsieveReport{}
	jsonBuf := make([]byte, jsonMaxSize)
	neededSize := uint32(0)

	// Perform the scan:
	ret, status, err := _peSieveScanEx.Call(
		uintptr(unsafe.Pointer(&pr)), // first pass the return variable
		uintptr(unsafe.Pointer(&pp)), // then pass the typical arguments of the function
		uintptr(rtype),
		uintptr(unsafe.Pointer(&jsonBuf[0])),
		uintptr(jsonMaxSize),
		uintptr(unsafe.Pointer(&neededSize)),
	)
	if neededSize > uint32(jsonMaxSize) {
		// The supplied buffer was too small to fit in the whole JSON report
		fmt.Printf("Couldn't retrieve the full buffer. Needed size: %x\n", neededSize)
	}
	
	// Print the obtained report:
	var reportStr = string(jsonBuf[:neededSize])
	
	// Some additional returned stuff:
	if (uintptr(unsafe.Pointer(&pr)) != ret) {
		fmt.Printf("Returned val invalid: %x vs %x\n", unsafe.Pointer(&pr) , ret)
	}
	if status != 0 {
		fmt.Println("Error:", err)
	}
	return pr, reportStr, neededSize
}
