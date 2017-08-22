#include "util.h"

bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size)
{
    ULONGLONG start = (ULONGLONG)buffer_bgn;
    ULONGLONG end = start + buffer_size;

    ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

    if ((ULONGLONG)field_bgn < start) {
        return false;
    }
    if (field_end >= end) {
        return false;
    }
    return true;
}
