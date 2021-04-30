#include "strings_util.h"
#include <strsafe.h>

#include <iomanip>
#include <algorithm>

std::string pesieve::util::to_lowercase(std::string str)
{
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	return str;
}

bool pesieve::util::is_cstr_equal(char const *a, char const *b, const size_t max_len)
{
	for (size_t i = 0; i < max_len; ++i) {
		if (tolower(a[i]) != tolower(b[i])) {
			return false;
		}
		if (tolower(a[i]) == '\0') break;
	}
	return true;
}

#define MIN(x,y) ((x) < (y) ? (x) : (y))

size_t pesieve::util::levenshtein_distance(const char s1[], const char s2[])
{
	const size_t MAX_LEN = 100;
	const size_t len1 = strlen(s1);
	const size_t len2 = strlen(s2);

	if (len1 >= MAX_LEN || len2 >= MAX_LEN) return(-1);

	//init the distance matrix
	int dist[MAX_LEN][MAX_LEN] = { 0 };
	for (int i = 0;i <= len1;i++) {
		dist[0][i] = i;
	}
	for (int j = 0;j <= len2; j++) {
		dist[j][0] = j;
	}
	// calculate
	for (int j = 1;j <= len1; j++) {
		for (int i = 1;i <= len2; i++) {
			int track = 1;
			if (s1[i - 1] == s2[j - 1]) {
				track = 0;
			}
			int t = MIN((dist[i - 1][j] + 1), (dist[i][j - 1] + 1));
			dist[i][j] = MIN(t, (dist[i - 1][j - 1] + track));
		}
	}
	return dist[len2][len1];
}

size_t pesieve::util::str_hist_diffrence(const char s1[], const char s2[])
{
	const size_t MAX_LEN = 255;
	size_t hist1[MAX_LEN] = { 0 };
	size_t hist2[MAX_LEN] = { 0 };

	const size_t len1 = strlen(s1);
	const size_t len2 = strlen(s2);

	for (size_t i = 0; i < strlen(s1); i++) {
		char c = tolower(s1[i]);
		hist1[c]++;
	}

	for (size_t i = 0; i < strlen(s2); i++) {
		char c = tolower(s2[i]);
		hist2[c]++;
	}

	size_t diffs = 0;
	for (size_t i = 0; i < MAX_LEN; i++) {
		if (hist2[i] == hist1[i]) continue;
		diffs++;
	}
	return diffs;
}