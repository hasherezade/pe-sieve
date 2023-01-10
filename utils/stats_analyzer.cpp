#include "stats_analyzer.h"

#define ENTROPY_DATA_TRESHOLD 1.5
#define ENTROPY_CODE_TRESHOLD ENTROPY_DATA_TRESHOLD
#define ENTROPY_ENC_TRESHOLD 6.0
#define ENTROPY_STRONG_ENC_TRESHOLD 7.0
using namespace pesieve::util;


double getValRatio(IN const AreaStats<BYTE>& stats, BYTE val)
{
	auto val_itr = stats.currArea.histogram.find(val);
	double ratio = 0;
	if (val_itr != stats.currArea.histogram.end()) {
		ratio = ((double)val_itr->second / (double)stats.currArea.size);
		//std::cout << "Val : " << std::hex << (UINT) val << " RATIO: " << ratio << "\n";
	}
	return ratio;
}

bool pesieve::util::isSuspicious(IN const AreaStats<BYTE>& stats, OUT AreaInfo& info)
{
	if (!stats.isFilled() || !stats.currArea.size) {
		return false;
	}

	const BYTE mFreqVal = util::getMostFrequentValue<BYTE>(stats.currArea.histogram);
	double entropy = stats.currArea.entropy;

	info.fullAreaObfuscated = (mFreqVal != 0 && entropy > ENTROPY_DATA_TRESHOLD); // possible XOR obfuscation, or block cipher
	info.fullAreaEncrypted = (entropy > ENTROPY_STRONG_ENC_TRESHOLD);// strong encryption
	if (mFreqVal != 0 && entropy > ENTROPY_ENC_TRESHOLD) {
		if (stats.currArea.frequencies.size() > 1) {
			auto fItr = stats.currArea.frequencies.begin(); // first one
			auto eItr = stats.currArea.frequencies.rbegin(); // last one
			// most common - least common ratio
			double diff = ((double)(eItr->first - fItr->first)) / (double)stats.currArea.size;
			//std::cout << "RATIO : " << fItr->first << " VS " << eItr->first << " DIFF: " << diff << "\n";
			if (diff < 0.01) {
				info.fullAreaEncrypted = true;
			}
		}
	}
	if (entropy > ENTROPY_CODE_TRESHOLD) { // possible code
		size_t points = 0;

		if (getValRatio(stats, 0xFF) > 0.02) points++;
		if (getValRatio(stats, 0x8B) > 0.02) points++;
		if (getValRatio(stats, 0xCC) > 0.001) points++;
		if (getValRatio(stats, 0x48) > 0.02) points++; // for x64
		//std::cout << "POINTS: " << points << "\n";
		if (points > 1) {
			info.possibleCode = true;
		}
	}
	const bool isEnc = (info.fullAreaEncrypted) ||
		info.fullAreaObfuscated || info.possibleCode;
	return isEnc;
}
