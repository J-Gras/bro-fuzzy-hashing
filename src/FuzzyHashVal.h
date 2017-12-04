// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_PLUGIN_JGRAS_FUZZYHASHING_VAL_H
#define BRO_PLUGIN_JGRAS_FUZZYHASHING_VAL_H

#include <OpaqueVal.h>

#include "fuzzy.h"

namespace plugin {
namespace JGras_FuzzyHashing {

class FuzzyHashVal : public HashVal {
protected:
	FuzzyHashVal() { };
	FuzzyHashVal(OpaqueType* t);

	//DECLARE_SERIAL(FuzzyHashVal);
};

class SSDeepVal : public FuzzyHashVal {
public:
	// TODO: static functionality?
	//static void digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH]);

	SSDeepVal();

protected:
	friend class Val;

	virtual bool DoInit() override;
	virtual bool DoFeed(const void* data, size_t size) override;
	virtual StringVal* DoGet() override;

	//DECLARE_SERIAL(SSDeepVal);

private:
	fuzzy_state* state;
};

}
}

#endif
