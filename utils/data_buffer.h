#pragma once
#include <windows.h>
#include "basic_buffer.h"

namespace pesieve {

    namespace util {

        struct ByteBuffer : public BasicBuffer
        {
            ByteBuffer()
                : BasicBuffer()
            {
            }

            ~ByteBuffer()
            {
                freeBuffer();
            }

            bool isValidPtr(BYTE * field_bgn, size_t field_size)
            {
                return peconv::validate_ptr(this->data, this->data_size, field_bgn, field_size);
            }

            bool isDataContained(const BYTE* rawData, size_t r_size)
            {
                size_t smaller_size = data_size > r_size ? r_size : data_size;
                if (::memcmp(data, rawData, smaller_size) == 0) {
                    return true;
                }
                return false;
            }

            bool allocBuffer(size_t size)
            {
                freeBuffer();
                data = peconv::alloc_aligned(size, PAGE_READWRITE);
                if (data == nullptr) {
                    return false;
                }
                data_size = size;
                padding = 0;
                return true;
            }

            void freeBuffer()
            {
                if (!data) {
                    data_size = 0;
                    padding = 0;
                    return;
                }
                peconv::free_aligned(data, data_size);
                data = nullptr;
                data_size = 0;
                padding = 0;
            }

        };

    }; // namespace util

}; // namespace pesieve

