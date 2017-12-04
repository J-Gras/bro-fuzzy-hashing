
#include "Plugin.h"

#include "FuzzyHash.h"

namespace plugin { namespace JGras_FuzzyHashing { Plugin plugin; } }

using namespace plugin::JGras_FuzzyHashing;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::file_analysis::Component("SSDeep",
		::plugin::JGras_FuzzyHashing::SSDeep::Instantiate));

	plugin::Configuration config;
	config.name = "JGras::FuzzyHashing";
	config.description = "Fuzzy hashing support for Bro";
	config.version.major = 0;
	config.version.minor = 2;
	return config;
	}
