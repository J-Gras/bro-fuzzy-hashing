// See the file "COPYING" in the main distribution directory for copyright.

// #include <Serializer.h>

#include "FuzzyHashVal.h"

#include <zeek/broker/Data.h>

#include <fuzzy.h>
#include <tlsh.h>

namespace plugin::JGras_FuzzyHashing {

using namespace zeek;

FuzzyHashVal::FuzzyHashVal(OpaqueTypePtr t) : HashVal(std::move(t))
	{
	}

static OpaqueTypePtr ssdeep_type = make_intrusive<OpaqueType>("ssdeep");

SSDeepVal::SSDeepVal() : FuzzyHashVal(ssdeep_type)
	{
	}

bool SSDeepVal::DoInit()
	{
	assert(! IsValid());
	state = fuzzy_new();
	return state != NULL;
	}

bool SSDeepVal::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	bool success = (fuzzy_update(state, static_cast<const u_char*>(data), size) == 0);
	return success;
	}

StringValPtr SSDeepVal::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	char hash[FUZZY_MAX_RESULT] = "";
	if (fuzzy_digest(state, hash, 0) != 0 )
		return val_mgr->EmptyString();

	fuzzy_free(state);
	return make_intrusive<StringVal>(hash);
	}

IMPLEMENT_OPAQUE_VALUE(SSDeepVal)

std::optional<BrokerData> SSDeepVal::DoSerializeData() const {
	//TODO: Implement serialization
	return std::nullopt;
}

bool SSDeepVal::DoUnserializeData(BrokerDataView) {
	//TODO: Impelment deserialization
	return false;
}

static OpaqueTypePtr tlsh_type = make_intrusive<OpaqueType>("tlsh");

TLSHVal::TLSHVal() : FuzzyHashVal(tlsh_type)
	{
	}

bool TLSHVal::SetHash(const char* hash_val)
	{
	return tlsh->fromTlshStr(hash_val) == 0;
	}

bool TLSHVal::DoInit()
	{
	assert(! IsValid());
	tlsh = new Tlsh();
	return tlsh != NULL;
	}

bool TLSHVal::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	/*for (int i = 0; i < size; i++) {
        fprintf(stderr, " %02x", ((u_char *) data)[i]);
    }
    fprintf(stderr, "\n");*/
	//fprintf(stderr, "%s", data);
	tlsh->update(static_cast<const u_char*>(data), size);

	return IsValid();
	}

StringValPtr TLSHVal::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	tlsh->final();
	const char* hash = tlsh->getHash();
	return make_intrusive<StringVal>(hash);
	}

IMPLEMENT_OPAQUE_VALUE(TLSHVal)

std::optional<BrokerData> TLSHVal::DoSerializeData() const {
	//TODO: Implement serialization
	return std::nullopt;
}

bool TLSHVal::DoUnserializeData(BrokerDataView) {
	//TODO: Impelment deserialization
	return false;
}

int TLSHVal::TotalDiff(const TLSHVal* other, bool len_diff) {
	auto other_tlsh = other->tlsh;
	return tlsh->totalDiff(other_tlsh, len_diff);
}

}
