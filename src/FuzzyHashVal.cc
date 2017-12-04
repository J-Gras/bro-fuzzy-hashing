// See the file "COPYING" in the main distribution directory for copyright.

// #include <Serializer.h>

#include "FuzzyHashVal.h"

using namespace plugin::JGras_FuzzyHashing;

FuzzyHashVal::FuzzyHashVal(OpaqueType* t) : HashVal(t)
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

static OpaqueType* ssdeep_type = new OpaqueType("ssdeep");

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

StringVal* SSDeepVal::DoGet()
	{
	if ( ! IsValid() )
		return new StringVal("");

	char hash[FUZZY_MAX_RESULT] = "";
	if (fuzzy_digest(state, hash, 0) != 0 )
		return new StringVal("");

	fuzzy_free(state);
	return new StringVal(hash);
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
