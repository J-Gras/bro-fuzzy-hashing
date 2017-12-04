
#include "Plugin.h"

#include "SSDeep.h"

namespace plugin { namespace JGras_SSDeep { Plugin plugin; } }

using namespace plugin::JGras_SSDeep;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::file_analysis::Component("SSDeep", ::plugin::JGras_SSDeep::SSDeep::Instantiate));

	plugin::Configuration config;
	config.name = "JGras::SSDeep";
	config.description = "Fuzzy hashing based on ssdeep-library";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
