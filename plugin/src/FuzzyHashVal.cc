// See the file "COPYING" in the main distribution directory for copyright.

// #include <Serializer.h>

#include "FuzzyHashVal.h"

#include <fuzzy.h>
#include <tlsh.h>

namespace plugin::JGras_FuzzyHashing {

using namespace zeek;

FuzzyHashVal::FuzzyHashVal(OpaqueTypePtr t) : HashVal(std::move(t))
	{
	}

/*
IMPLEMENT_SERIAL(FuzzyHashVal, SER_FUZZY_HASH_VAL);

bool FuzzyHashVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FUZZY_HASH_VAL, OpaqueVal);
	return SERIALIZE(valid);
	}

bool FuzzyHashVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);
	return UNSERIALIZE(&valid);
	}
*/

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

/*
IMPLEMENT_SERIAL(SSDeepVal, SER_SSDEEP_VAL);

bool SSDeepVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SSDEEP_VAL, HashVal);

	if ( ! IsValid() )
		return true;

	if ( ! (SERIALIZE(ctx.A) &&
		SERIALIZE(ctx.B) &&
		SERIALIZE(ctx.C) &&
		SERIALIZE(ctx.D) &&
		SERIALIZE(ctx.Nl) &&
		SERIALIZE(ctx.Nh)) )
		return false;

	for ( int i = 0; i < MD5_LBLOCK; ++i )
		{
		if ( ! SERIALIZE(ctx.data[i]) )
			return false;
		}

	if ( ! SERIALIZE(ctx.num) )
		return false;

	return true;
	}

bool SSDeepVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(FuzzyHashVal);

	if ( ! IsValid() )
		return true;

	if ( ! (UNSERIALIZE(&ctx.A) &&
		UNSERIALIZE(&ctx.B) &&
		UNSERIALIZE(&ctx.C) &&
		UNSERIALIZE(&ctx.D) &&
		UNSERIALIZE(&ctx.Nl) &&
		UNSERIALIZE(&ctx.Nh)) )
		return false;

	for ( int i = 0; i < MD5_LBLOCK; ++i )
		{
		if ( ! UNSERIALIZE(&ctx.data[i]) )
			return false;
		}

	if ( ! UNSERIALIZE(&ctx.num) )
		return false;

	return true;
}
*/

static OpaqueTypePtr tlsh_type = make_intrusive<OpaqueType>("tlsh");

TLSHVal::TLSHVal() : FuzzyHashVal(tlsh_type)
	{
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
}
