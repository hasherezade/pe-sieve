#include "stats_analyzer.h"

#define ENTROPY_CODE_TRESHOLD 1.5
#define ENTROPY_ENC_TRESHOLD 6.0

using namespace pesieve::util;

bool pesieve::util::isSuspicious(IN const AreaStats<BYTE>& stats, OUT AreaInfo& info)
{
	if (!stats.isFilled()) {
		return false;
	}

	const BYTE mFreqVal = util::getMostFrequentValue<BYTE>(stats.currArea.histogram);
	double entropy = stats.currArea.entropy;

	info.fullAreaObfuscated = (mFreqVal != 0 && entropy > ENTROPY_CODE_TRESHOLD); // possible XOR obfuscation, or block cipher
	info.fullAreaEncrypted = entropy > ENTROPY_ENC_TRESHOLD; // strong encryption
	info.containsEncryptedBlocks = (stats.biggestChunk != nullptr) ? (stats.biggestChunk->entropy > ENTROPY_ENC_TRESHOLD) : false;

	const bool isEnc = (info.fullAreaEncrypted) ||
		(info.fullAreaObfuscated && info.containsEncryptedBlocks);

	return isEnc;
}
