#pragma once

#include <Windows.h>
#include <iostream>
#include <map>

class Node
{
public:

	static bool addPattern(Node* rootN, const BYTE *pattern, size_t pattern_size)
	{
		if (!rootN || !pattern) return false;

		Node* next = rootN;
		for (size_t i = 0; i < pattern_size; i++) {
			next = next->addNext(pattern[i]);
			if (!next) return false;
		}
		return true;
	}

	//---

	Node()
		: level(0)
	{
		this->val = 0;
	}

	Node(BYTE _val, size_t _level)
		: level(_level), val(_val)
	{
	}

	Node* getNode(BYTE _val)
	{
		auto found = immediates.find(_val);
		if (found != immediates.end()) {
			return found->second;
		}
		return nullptr;
	}

	Node* addNext(BYTE _val)
	{
		Node* nextN = getNode(_val);
		if (!nextN) {
			nextN = new Node(_val, this->level + 1);
			immediates[_val] = nextN;
		}
		return nextN;
	}

	void print()
	{
		std::cout << std::hex << (unsigned int)val << " [" << level << "]" << " [" << immediates.size() << "]";
		if (!immediates.size()) {
			printf("\n");
			return;
		}
		for (auto itr = immediates.begin(); itr != immediates.end(); ++itr) {
			itr->second->print();
		}
	}

	bool isMatching(const BYTE* data, size_t data_size)
	{
		Node* curr = this;
		for (size_t i = 0; i < data_size; i++)
		{
			if (curr->isEnd()) return true;
			BYTE val = data[i];
			curr = curr->getNode(val);
			if (!curr) return false;
		}
		return false;
	}

	bool isEnd()
	{
		return this->immediates.size() ? false : true;
	}

protected:
	BYTE val;
	size_t level;
	std::map<BYTE, Node*> immediates;
};

