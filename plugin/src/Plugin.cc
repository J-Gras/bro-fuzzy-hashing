#include "config.h"
#include "Plugin.h"
#include "FuzzyHash.h"

#include <zeek/file_analysis/Component.h>

namespace zeek::plugin::JGras_FuzzyHashing { Plugin plugin; }

using namespace zeek::plugin::JGras_FuzzyHashing;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::file_analysis::Component("SSDeep",
		::plugin::JGras_FuzzyHashing::SSDeep::Instantiate));
	AddComponent(new zeek::file_analysis::Component("TLSH",
		::plugin::JGras_FuzzyHashing::TLSH::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "JGras::FuzzyHashing";
	config.description = "Fuzzy hashing support for Zeek";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
