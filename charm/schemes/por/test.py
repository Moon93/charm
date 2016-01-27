from PublicProofOfRetrievability import *
proof = VerifiableProofOfRetrievability() #initialize
keys = proof.keygen() #generate a keypair
message = b"alsfhjklasjkhdflasdjkfhasjkdfuasizerasfuzhcuzsydhfckyuhcdzkyfdgyknxdfjgykdfhgdksfjhgaskdjhfgaskdjhfgaskdfhjgaskdfjhgaskdfjhgaskdfjhgaskdfjhgasdkfhgasdfkasjhgdfkasfdhgaskdfhgasdfksdcfahbkuanzeserfbnekuasfgbkegeknfasefasefrvafahkjfbcgasdkfzuhsenrkfjzxtnuaegfknahsjfgahkdfucxtngekurtzukansfxezhxcfkfzxsetzhnseskcezhjfnfcefrkuzasehfghadsfgkasdfgasfdgsadfgkdsafghfdasghfsdagsdafhgfuziewrzuiewrzuwerzuiasfdhfdsahjfsadhjsafhjafdsghafdsghjfdsaghsfadghjrztuweqinrthaxfskezansetxgnfuyueshfkn"
splitm = proof.splitMessage(message) #split the message
x = keys[0]
v = keys[1]
testsignature = proof.generateSignature(splitm, 1, x) #test the function generateSignature
challenge = proof.generateChallenge(splitm, 4) #generate a challenge
response = proof.proove(splitm, challenge, x) #generate the response
proof.verify(response, challenge, v) #proove?
