// See the file "COPYING" in the main distribution directory for copyright.

#include "FuzzyHash.h"

#include <zeek/file_analysis/Manager.h>

namespace plugin::JGras_FuzzyHashing {

using namespace zeek;

StringValPtr SSDeep::kind_val = make_intrusive<StringVal>("ssdeep");
StringValPtr TLSH::kind_val = make_intrusive<StringVal>("tlsh");

FuzzyHash::FuzzyHash(RecordValPtr args, file_analysis::File* file, FuzzyHashVal* hv,
	StringValPtr arg_kind)
	: file_analysis::Analyzer(file_mgr->GetComponentTag(util::to_upper(arg_kind->ToStdString())), std::move(args), file),
	  fuzzy_hash(hv),
	  fed(false),
	  kind(std::move(arg_kind))
	{
	fuzzy_hash->Init();
	}

FuzzyHash::~FuzzyHash()
	{
	Unref(fuzzy_hash);
	}

bool FuzzyHash::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! fuzzy_hash->IsValid() )
		return false;

	if ( ! fed )
		fed = len > 0;

	fuzzy_hash->Feed(data, len);
	return true;
	}

bool FuzzyHash::EndOfFile()
	{
	Finalize();
	return false;
	}

bool FuzzyHash::Undelivered(uint64_t offset, uint64_t len)
	{
	return true;
	}

void FuzzyHash::Finalize()
	{
	if ( ! fuzzy_hash->IsValid() || ! fed )
		return;

	if ( ! file_fuzzy_hash )
		return;

	event_mgr.Enqueue(file_fuzzy_hash, GetFile()->ToVal(), kind, fuzzy_hash->Get());
}

}