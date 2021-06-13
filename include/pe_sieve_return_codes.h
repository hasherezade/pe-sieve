#pragma once

// return codes for PE-sieve.exe:
typedef enum {
    PESIEVE_ERROR = (-1),
    PESIEVE_INFO = 0,
    PESIEVE_NOT_DETECTED = 1,
    PESIEVE_DETECTED = 2
} t_pesieve_res;
