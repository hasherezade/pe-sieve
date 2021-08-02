/**
* @file
* @brief   The codes returned by the PE-sieve EXE
*/

#pragma once

// return codes for PE-sieve.exe:
typedef enum {
	PESIEVE_ERROR = (-1),   ///< the scan has failed, PE-sieve returned an error
	PESIEVE_INFO = 0,   ///< PE-sieve was deployed in the info mode (i.e. displaying help)
	PESIEVE_NOT_DETECTED = 1, ///< the process was scanned successfuly, and NO suspicious indicators are detected
	PESIEVE_DETECTED = 2   ///< the process was scanned successfuly, and some suspicious indicators are detected
} t_pesieve_res;
