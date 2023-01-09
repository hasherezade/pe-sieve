#include "stats_analyzer.h"

#define ENTROPY_DATA_TRESHOLD 1.5
#define ENTROPY_CODE_TRESHOLD 5.5
#define ENTROPY_ENC_TRESHOLD 6.0
#define ENTROPY_STRONG_ENC_TRESHOLD 7.0
using namespace pesieve::util;

bool pesieve::util::isSuspicious(IN const AreaStats<BYTE>& stats, OUT AreaInfo& info)
{
	if (!stats.isFilled()) {
		return false;
	}

	const BYTE mFreqVal = util::getMostFrequentValue<BYTE>(stats.currArea.histogram);
	double entropy = stats.currArea.entropy;

	info.fullAreaObfuscated = (mFreqVal != 0 && entropy > ENTROPY_DATA_TRESHOLD); // possible XOR obfuscation, or block cipher
	info.fullAreaEncrypted = (entropy > ENTROPY_STRONG_ENC_TRESHOLD) || (mFreqVal != 0 && entropy > ENTROPY_ENC_TRESHOLD); // strong encryption
	if (entropy > ENTROPY_CODE_TRESHOLD) { // possible code
		double ff_ratio = ((double)stats.currArea.histogram.at(0xFF) / (double)stats.currArea.size);
		double cc_ratio = ((double)stats.currArea.histogram.at(0xCC) / (double)stats.currArea.size);
		if (ff_ratio > 0.01 && cc_ratio > 0.001) {
			info.possibleCode = true;
		}
	}
	const bool isEnc = (info.fullAreaEncrypted) ||
		(info.fullAreaObfuscated && info.possibleCode);

	return isEnc;
}
