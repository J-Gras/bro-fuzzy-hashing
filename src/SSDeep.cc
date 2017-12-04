// See the file "COPYING" in the main distribution directory for copyright.

#include "SSDeep.h"
#include "events.bif.h"

#include <file_analysis/Manager.h>

using namespace plugin::JGras_SSDeep;

SSDeep::SSDeep(RecordVal* args, file_analysis::File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("SSDEEP"), args, file),
	  fed(false)
	{
	//Hash->Init();
	state = fuzzy_new();
	}

SSDeep::~SSDeep()
	{
	//Unref(Hash);
	fuzzy_free(state);
	}

file_analysis::Analyzer* SSDeep::Instantiate(RecordVal* args, file_analysis::File* file)
	{
	return file_hash_ssdeep ? new SSDeep(args, file) : 0;
	}

bool SSDeep::DeliverStream(const u_char* data, uint64 len)
	{
	if ( ! fed )
		fed = len > 0;

	//Hash->Feed(data, len);
	bool success = (fuzzy_update(state, data, len) == 0);
	return success;
	}

bool SSDeep::EndOfFile()
	{
	Finalize();
	return false;
	}

bool SSDeep::Undelivered(uint64 offset, uint64 len)
	{
	return false;
	}

void SSDeep::Finalize()
	{
	char hash[FUZZY_MAX_RESULT] = "";
	//if ( ! hash->IsValid() || ! fed )
	//	return;
	if (fuzzy_digest(state, hash, 0) != 0 )
		return;

	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(new StringVal(hash));

	mgr.QueueEvent(file_hash_ssdeep, vl);
}
