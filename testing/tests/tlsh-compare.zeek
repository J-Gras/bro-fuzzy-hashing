# @TEST-DOC: Test comparison functions.
#
# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

const data = "TLSH is a fuzzy matching library. Given a byte stream with a minimum length of 50 bytes TLSH generates a hash value which can be used for similarity comparisons. Similar objects will have similar hash values which allows for the detection of similar objects by comparing their hash values. Note that the byte stream should have a sufficient amount of complexity. For example, a byte stream of identical bytes will not generate a hash value.";

event zeek_init()
	{
	local tlsh_handle_a = tlsh_hash_init();
	tlsh_hash_update(tlsh_handle_a, data);
	local tlsh_handle_a2 = tlsh_hash_init();
	tlsh_hash_update(tlsh_handle_a2, data);
	local tlsh_handle_b = tlsh_hash_init();
	tlsh_hash_update(tlsh_handle_b, data + "This is different.");

	local tlsh_hash_a = tlsh_hash_finish(tlsh_handle_a);
	print fmt("tlsh_a  = %s", tlsh_hash_a);
	local tlsh_hash_a2 = tlsh_hash_finish(tlsh_handle_a2);
	print fmt("tlsh_a2 = %s", tlsh_hash_a2);
	local tlsh_hash_b = tlsh_hash_finish(tlsh_handle_b);
	print fmt("tlsh_b  = %s", tlsh_hash_b);

	print fmt("a vs. a2 = %s", tlsh_total_diff(tlsh_handle_a, tlsh_handle_a2));
	print fmt("a vs. b  = %s", tlsh_total_diff(tlsh_handle_a, tlsh_handle_b));
	print fmt("b vs. a  = %s", tlsh_total_diff(tlsh_handle_b, tlsh_handle_a));
	print fmt("b vs. b  = %s", tlsh_total_diff(tlsh_handle_b, tlsh_handle_b));
	}
