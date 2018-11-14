# @TEST-EXEC: bro -NN JGras::FuzzyHashing |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
