# @TEST-DOC: Test conversion functions.
#
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

const data = "TLSH is a fuzzy matching library. Given a byte stream with a minimum length of 50 bytes TLSH generates a hash value which can be used for similarity comparisons. Similar objects will have similar hash values which allows for the detection of similar objects by comparing their hash values. Note that the byte stream should have a sufficient amount of complexity. For example, a byte stream of identical bytes will not generate a hash value.";

event zeek_init()
	{
	local tlsh_handle_a = tlsh_hash_init();
	tlsh_hash_update(tlsh_handle_a, data);
	print fmt("tlsh_a      = %s", tlsh_hash_finish(tlsh_handle_a));

	local tlsh_handle_b = tlsh_hash_init();
	local tlsh_succ_b = tlsh_from_string(tlsh_handle_b, "78F05C52EF1CE353438E4241630696C7A91980200256D69C849DC616440AC1968F70DD");
	print fmt("tlsh_b (%s)  = %s", tlsh_succ_b, tlsh_hash_finish(tlsh_handle_b));

	local tlsh_handle_c = tlsh_hash_init();
	local tlsh_succ_c = tlsh_from_string(tlsh_handle_c, "ThisIsNotAValidHash");
	print fmt("tlsh_c (%s)  = %s", tlsh_succ_c, tlsh_hash_finish(tlsh_handle_c));
	}
