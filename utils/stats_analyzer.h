#pragma once

#include "stats.h"

namespace pesieve {

    namespace util {

        struct AreaInfo
        {
            AreaInfo()
                : fullAreaObfuscated(false),
                fullAreaEncrypted(false),
                containsEncryptedBlocks(false)
            {
            }

            // Copy constructor
            AreaInfo(const AreaInfo& p1)
                : fullAreaObfuscated(p1.fullAreaObfuscated),
                fullAreaEncrypted(p1.fullAreaEncrypted),
                containsEncryptedBlocks(p1.containsEncryptedBlocks)
            {
            }

            const virtual bool toJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"area_info\" : {\n");
                fieldsToJSON(outs, level + 1);
                outs << "\n";
                OUT_PADDED(outs, level, "}");
                return true;
            }

            const virtual void fieldsToJSON(std::stringstream& outs, size_t level)
            {
                OUT_PADDED(outs, level, "\"is_full_obfuscated\" : ");
                outs << std::dec << fullAreaObfuscated;
                outs << ",\n";

                OUT_PADDED(outs, level, "\"is_full_encrypted\" : ");
                outs << std::dec << fullAreaEncrypted;
                outs << ",\n";

                OUT_PADDED(outs, level, "\"has_encrypted_blocks\" : ");
                outs << std::dec << containsEncryptedBlocks;
            }

            bool fullAreaObfuscated;
            bool fullAreaEncrypted;
            bool containsEncryptedBlocks;
        };

        bool isSuspicious(IN const AreaStats<BYTE>& stats, OUT AreaInfo& info);

    } //namespace util

}; // namespace pesieve
