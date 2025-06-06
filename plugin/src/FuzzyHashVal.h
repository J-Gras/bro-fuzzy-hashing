// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include <zeek/OpaqueVal.h>

// Forward declarations
struct fuzzy_state;
class Tlsh;

namespace plugin::JGras_FuzzyHashing {

class FuzzyHashVal : public zeek::HashVal {
protected:
	//FuzzyHashVal() { };
	FuzzyHashVal(zeek::OpaqueTypePtr t);
};

class SSDeepVal : public FuzzyHashVal {
public:
	// TODO: static functionality?
	//static void digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH]);

	SSDeepVal();

protected:
	friend class Val;

	bool DoInit() override;
	bool DoFeed(const void* data, size_t size) override;
	zeek::StringValPtr DoGet() override;

	DECLARE_OPAQUE_VALUE_DATA(SSDeepVal)

private:
	fuzzy_state* state;
};

class TLSHVal : public FuzzyHashVal {
public:
	// TODO: static functionality?
	//static void digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH]);

	TLSHVal();
	int TotalDiff(const TLSHVal* other, bool len_diff);

protected:
	friend class Val;

	bool DoInit() override;
	bool DoFeed(const void* data, size_t size) override;
	zeek::StringValPtr DoGet() override;

	DECLARE_OPAQUE_VALUE_DATA(TLSHVal)

private:
	Tlsh* tlsh;
};

}
