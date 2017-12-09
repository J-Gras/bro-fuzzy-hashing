// See the file "COPYING" in the main distribution directory for copyright.

#include "FuzzyHash.h"

#include <file_analysis/Manager.h>

using namespace plugin::JGras_FuzzyHashing;

FuzzyHash::FuzzyHash(RecordVal* args, file_analysis::File* file, FuzzyHashVal* hv,
	const char* arg_kind)
	: file_analysis::Analyzer(file_mgr->GetComponentTag(to_upper(arg_kind).c_str()), args, file),
	  fuzzy_hash(hv),
	  fed(false),
	  kind(arg_kind)
	{
	fuzzy_hash->Init();
	}

FuzzyHash::~FuzzyHash()
	{
	Unref(fuzzy_hash);
	}

bool FuzzyHash::DeliverStream(const u_char* data, uint64 len)
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

bool FuzzyHash::Undelivered(uint64 offset, uint64 len)
	{
	return true;
	}

void FuzzyHash::Finalize()
	{
	if ( ! fuzzy_hash->IsValid() || ! fed )
		return;

	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(new StringVal(kind));
	vl->append(fuzzy_hash->Get());

	mgr.QueueEvent(file_fuzzy_hash, vl);
}
