from PublicProofOfRetrievability import *
proof = VerifiableProofOfRetrievability() #initialize
#proof.setP(307)
keys = proof.keygen() #generate a keypair
message = b"aaaaasdfkhasdfhsahkdfhsadfkjashdfkajshgkasdsagdhfsadjfhasldfjhasldfhsaldfjhlsadfhlsadjfhsaldjfashfsalhsaldfhjasldflfdhkjsdflsdafsalhdrciuaznrfaildkufhallsadfkjashdflaskjdhflasdkjfhasldfkjhasldfkjhaa"
splitm = proof.splitMessage(message) #split the message
x = keys[0]
v = keys[1]
testsignature = proof.generateSignature(splitm, 1, x) #test the function generateSignature
#challenge = proof.generateChallenge(splitm, 4) #generate a challenge
challenge = [(0,1337)]
response = proof.proove(splitm, challenge, x) #generate the response
proof.verify(response, challenge, v) #proove?
