package cipher_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/DanielKrawisz/bmutil"
	. "github.com/DanielKrawisz/bmutil/cipher"
	"github.com/DanielKrawisz/bmutil/hash"
	"github.com/DanielKrawisz/bmutil/identity"
	"github.com/DanielKrawisz/bmutil/pow"
	"github.com/DanielKrawisz/bmutil/wire"
	"github.com/DanielKrawisz/bmutil/wire/obj"
	"github.com/btcsuite/btcd/btcec"
)

// TestPubKeys tests GeneratePubKey, SignAndEncryptPubKey and
// TryDecryptAndVerifyPubKey
func TestPubKeys(t *testing.T) {
	// GeneratePubKey

	// Version 4 address
	{
		pk, err := GeneratePubKey(PrivID1, time.Hour*24)
		if err != nil {
			t.Error(err)
		}
		pkMsg := pk.Object()
		version := pkMsg.Header().Version
		if version != PrivID1.Address.Version {
			t.Errorf("For version expected %d got %d", PrivID1.Address.Version,
				version)
		}
		_, err = TryDecryptAndVerifyPubKey(pkMsg, &PrivID1.Address)
		if err != nil {
			t.Error(err)
		}
	}

	// Version 3 address
	{
		v3ID := *PrivID1
		v3ID.Address.Version = 3
		pk, err := GeneratePubKey(&v3ID, time.Hour*24)
		if err != nil {
			t.Error(err)
		}
		pkMsg := pk.Object()
		version := pkMsg.Header().Version
		if version != 3 {
			t.Errorf("For version expected %d got %d", PrivID1.Address.Version,
				version)
		}
		pk, err = TryDecryptAndVerifyPubKey(pkMsg, &v3ID.Address)
		if err != nil {
			t.Error(err)
		}
	}

	// Version 2 address
	{
		v2ID := *PrivID1
		v2ID.Address.Version = 2
		pk, err := GeneratePubKey(&v2ID, time.Hour*24)
		pkMsg := pk.Object()
		version := pkMsg.Header().Version
		if err != nil {
			t.Error(err)
		}
		if version != 2 {
			t.Errorf("For version expected %d got %d", PrivID1.Address.Version,
				version)
		}
		if !bytes.Equal(v2ID.SigningKey.PubKey().SerializeUncompressed()[1:],
			pk.VerificationKey()[:]) ||
			!bytes.Equal(v2ID.DecryptionKey.PubKey().SerializeUncompressed()[1:],
				pk.EncryptionKey()[:]) {
			t.Error("Signing/encryption key mismatch.")
		}
	}

	// TryDecryptAndVerifyPubKey
	{
		pubKey1 := TstNewDecryptedPubKey(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, 0, SignKey1, EncKey1, 1000, 1000, nil, Tag1, nil, PrivID1)

		var b bytes.Buffer
		pubKey1.Object().Encode(&b)

		encPubKey1 := new(obj.EncryptedPubKey)
		encPubKey1.Decode(bytes.NewReader(b.Bytes()))
		pubKey1Temp, err := TryDecryptAndVerifyPubKey(encPubKey1, &PrivID1.Address)
		if err != nil {
			t.Errorf("for TryDecryptAndVerifyPubKey got error %v", err)
		}
		if !reflect.DeepEqual(pubKey1, pubKey1Temp) {
			t.Errorf("decrypted pubkey not the same as original, got %v want %v",
				pubKey1Temp, pubKey1)
		}
	}

	{
		pubKey2 := TstNewExtendedPubKey(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, 0, SignKey2, EncKey2, 1000, 1000, PrivID2)

		var b bytes.Buffer
		pubKey2.Object().Encode(&b)

		encPubKey2 := new(obj.ExtendedPubKey)
		encPubKey2.Decode(bytes.NewReader(b.Bytes()))
		pubKey2Temp, err := TryDecryptAndVerifyPubKey(encPubKey2, &PrivID1.Address)
		if err != nil {
			t.Errorf("for TryDecryptAndVerifyPubKey got error %v", err)
		}
		if !reflect.DeepEqual(pubKey2, pubKey2Temp) {
			t.Errorf("decrypted pubkey not the same as original, got %v want %v",
				pubKey2Temp, pubKey2)
		}
	}

	addr, _ := bmutil.DecodeAddress("BM-2cTFEueNqmjgR3EqduEZmaZbEW1h9z7M7o")
	// Test actual encrypted pubkey
	{
		data, _ := hex.DecodeString("00000000025A04D60000000055A4EA7C0000000104017F933D64A866DE24C27D647C74068A59DCEE0CABFC1DF887BE7DD30BA3BD9143D513F0B37087891F6A98DD0B55B1A73E02CA002090CE6A050E760F52D18F7F50B1B9139DBCEF861254C195173AA601DE8A72B52E00206FAF91EDD32E213097CD91E4ACBB883CB2F8CC6AAFCC670DDE1FAC52C210469D71B08A162E07C4B8926A50CC0701594AF55D65052C2D9D74CE28BB571D781423C101BDC8DB6CE3FA639BDDE9CE39364307188470AEC410F7EE2BCC008CA6B1F2A37CF0841FC5EDE154C172438061577FBF3BC6BCDAAAB9BBCC90378DE815A99B0B78D81DFC9ABE33F99B4BC2AFAC2101ED7E0E213C00011FF3583B1E2BAADEF4BED2DB17F340258C22D38F8B490040B94E01F76F2118D90D718FFAFFB7D8F2A9F2B3498D45D528F16BCE55B43E63AAF3AED720F0AC06FCEB853661ACE13714069AA47A3D2FD6180AD0458B344E7AF04A26A25490DCEF236EE29CDF2FD96CDF55EB2B0D4DACA1EC21B4049DB6A6C713A2350D6ECE4C77C01DA01BCAAB2F2CBB31")
		pubkey, err := obj.DecodePubKey(bytes.NewReader(data))
		if err != nil {
			t.Fatal("failed to decode pubkey, got error", err)
		}

		_, err = TryDecryptAndVerifyPubKey(pubkey, addr)
		if err != nil {
			t.Errorf("failed to decrypt pubkey, got error %v", err)
		}
	}

	// Test actual unencrypted pubkey
	{
		data, _ := hex.DecodeString("0000000001FB575F000000005581B73A00000001030100000001520A752F43BD36DA5BD2C77FDB7E53C597EB21BDA6BD08A80AC2F4ACC3D885DE19945F02D6D18A655FD831F071B6224E0F145F7C3138BE07DB7C4C9C8BD234DD8333DA6BA201B9893982B28B740AB6252E3A146677A1EDE15F567F15D8E8C83EAD7547AC132D008418330810243A43DBCF2DD39C5283913ED6BD6C1A3B468271FD03E8FD03E8473045022100AB37F26D1709E43FD24852273033D97764F2498E170422EDC6775FADE21F7A9502206FEB2527BBCAF77E7D07BAF6FCD2F4ED49B8B4D1C3FCE7DEB6149D7E9DF3CD95")
		pubkey, err := obj.DecodePubKey(bytes.NewReader(data))
		if err != nil {
			t.Fatal("failed to decode pubkey, got error", err)
		}

		_, err = TryDecryptAndVerifyPubKey(pubkey, addr)
		if err != nil {
			t.Errorf("failed to verify pubkey, got error %v", err)
		}
	}

	// Test errors for TryDecryptAndVerifyPubKey

	randId, _ := btcec.NewPrivateKey(btcec.S256())
	invDec, _ := btcec.Encrypt(randId.PubKey(), []byte{0x00})
	undecData, _ := btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		[]byte{0x00})
	validPubKey, _ := wire.NewPubKey(randId.PubKey().SerializeUncompressed()[1:])

	forwardingData := TstGenerateForwardingData(validPubKey)
	invalidSig := TstGenerateInvalidSig()
	mismatchSig := TstGenerateMismatchSig()

	tests2 := []struct {
		pubkey  obj.Object
		address *bmutil.Address
	}{
		// Invalid tag.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag2, nil), &PrivID1.Address},

		// Invalid decryption key.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag1, invDec), &PrivID1.Address},

		// Decryption failure.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag1, []byte{0x00, 0x00}), &PrivID1.Address},

		// Undecodable decrypted data.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag1, undecData), &PrivID1.Address},

		// Invalid embedded signing key.
		{obj.NewExtendedPubKey(0, time.Now().Add(time.Minute*5), 1,
			&obj.PubKeyData{
				Behavior:        0,
				VerificationKey: &wire.PubKey{},
				EncryptionKey:   nil,
				Pow: &pow.Data{
					NonceTrialsPerByte: 1000,
					ExtraBytes:         1000,
				},
			}, nil), &PrivID1.Address},

		// Invalid embedded encryption key.
		{obj.NewExtendedPubKey(0, time.Now().Add(time.Minute*5), 1,
			&obj.PubKeyData{
				Behavior:        0,
				VerificationKey: validPubKey,
				EncryptionKey:   &wire.PubKey{},
				Pow: &pow.Data{
					NonceTrialsPerByte: 1000,
					ExtraBytes:         1000,
				},
			}, nil),
			&PrivID1.Address},

		// Surreptitous forwarding attack.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag1, forwardingData), &PrivID1.Address},

		// Invalid signature.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag1, invalidSig), &PrivID1.Address},

		// Signature mismatch.
		{obj.NewEncryptedPubKey(0, time.Now().Add(time.Minute*5), 1, Tag1, mismatchSig), &PrivID1.Address},
	}

	for i, test := range tests2 {
		if test.pubkey == nil {
			t.Fatalf("test case #%d is nil.", i)
		}
		_, err := TryDecryptAndVerifyPubKey(test.pubkey, test.address)
		if err == nil {
			t.Errorf("for test case #%d didn't get error", i)
		}
	}
}

// TestBroadcasts tests signing and encrypting broadcasts and
// decrypting and verifying broadcasts.
func TestBroadcasts(t *testing.T) {

	// SignAndEncryptBroadcast

	// v5 broadcast
	tag1, _ := hash.NewSha(PrivID1.Address.Tag())

	broadcast1, err := SignAndEncryptBroadcast(
		TstBroadcastEncryptParams(time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, tag1, 4, 1, 1, SignKey1, EncKey1,
			1000, 1000, 1, []byte("Hey there!"), PrivID1))
	if err != nil {
		t.Errorf("for SignAndEncryptBroadcast got error %v", err)
	}

	// v4 broadcast
	broadcast2ID := *PrivID1
	broadcast2ID.Address.Version = 3

	broadcast2, err := SignAndEncryptBroadcast(
		TstBroadcastEncryptParams(time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, nil, 3, 1, 1, SignKey1, EncKey1,
			1000, 1000, 1, []byte("Hey there!"), &broadcast2ID))
	if err != nil {
		t.Errorf("for SignAndEncryptBroadcast got error %v", err)
	}

	// TryDecryptAndVerifyBroadcast

	var b bytes.Buffer
	broadcast1.Object().Encode(&b)

	broadcast1Temp := new(obj.TaggedBroadcast)
	broadcast1Temp.Decode(bytes.NewReader(b.Bytes()))
	broadcast1Decrypted, err := TryDecryptAndVerifyBroadcast(broadcast1Temp, &PrivID1.Address)
	if err != nil {
		t.Errorf("for TryDecryptAndVerifyBroadcast got error %v", err)
	}
	if !reflect.DeepEqual(broadcast1, broadcast1Decrypted) {
		t.Errorf("decrypted broadcast not the same as original, got %v want %v",
			broadcast1Decrypted, broadcast1)
	}

	b.Reset()
	broadcast2.Object().Encode(&b)

	broadcast2Temp := new(obj.TaglessBroadcast)
	broadcast2Temp.Decode(bytes.NewReader(b.Bytes()))

	broadcast2Decrypted, err := TryDecryptAndVerifyBroadcast(broadcast2Temp, &broadcast2ID.Address)
	if err != nil {
		t.Errorf("for TryDecryptAndVerifyBroadcast got error %v", err)
	}
	if !reflect.DeepEqual(broadcast2, broadcast2Decrypted) {
		t.Errorf("decrypted broadcast not the same as original, got %v want %v",
			broadcast2Decrypted, broadcast2)
	}

	// Test actual v4 broadcast
	addr, _ := bmutil.DecodeAddress("BM-2D9ZrtqKDfEWzGaJzkef9d2VnVdNBTg7HL")
	data, _ := hex.DecodeString("000000000036D175000000005586BD320000000304011F41F946C4AE73F7C88A1ECF2F3E2B4302CA00201D7DEF4D03CD28A6B29138B5C64A75700BE12F95E4BB8DDF058AFB489FE753F200208F9A7916B652B10A5F4E455657946D4B0CC8401E0E6D1280DFA564729DE5CE22C1D5B1600BFC24784380E0DAF9A4A8458E2D90C1E12AFBB2245EC28AFA50F614C0F041F9E727A4CC69A28DBB5D0AE40754157E97CE5AD69C7BDA653364D33D4D3DD767E94793B099293E01513ECAF113B5B89A18B737DE8E17F089F97087C4D4E625C49E426FB1F2FABA345FB80C3D75D848D6D5BD8EC3763A410172334878CD4F49D525DFE65C37869F23B31F596D6FBDE84804E4D07F2D6609737D1506242F4CE2A8488128879F8DCB9EE94DCF6FAB836F5024CCE018938D1AB962E165602D12B0A1D3FA61E1EC226C5242283C6443BAF40B8E99C86F53D035F516266CC88AA0FC6FDAA5AEE08D44BF0F663EF9B19D908BF0BB2F4B64430BDDEE9E6990792DA1AB19C01CDA2FE4DD761849476D7DA52D9541995A0B0C6E1ADAA48D59985A34022CA62265588BF0E86878EAED5135BF85C3433A728E023833DDDAF8DC507AA2B46277D83CC314F1D850F600B79A1FC9")
	taglessBroadcast := new(obj.TaglessBroadcast)
	err = taglessBroadcast.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal("failed to decode broadcast, got error", err)
	}

	_, err = TryDecryptAndVerifyBroadcast(taglessBroadcast, addr)
	if err != nil {
		t.Errorf("failed to decrypt broadcast, got error %v", err)
	}

	// Test actual v5 broadcast
	addr, _ = bmutil.DecodeAddress("BM-2cTFEueNqmjgR3EqduEZmaZbEW1h9z7M7o")
	data, _ = hex.DecodeString("00000000000D53A6000000005585CC2B0000000305017F933D64A866DE24C27D647C74068A59DCEE0CABFC1DF887BE7DD30BA3BD9143B610A581CA91E470A5D99708A9213FFB02CA002057928F7E090BBD6ECF1106F6C537D1D2BB62D3DAF944DF18C81E1831C6F861F90020FC4FEEA130DC82532B91C616ADA50A581942D142E146C69CE6E6D7B020C69B1A5EF15B5C21A3CF563746170A67917FF31D0FA0DEB275F4CAC5D1C6654EB527C2C0BD67D721E632148E07AE2189A01C535E88BFABCECD207C86517CD5A9C527EF2269A59C5E160E64B3B397422181BD1406226CD63C4EE0C968AB83896C567CDF94F2192486B633EE6E89CB634AC48F237A84D24035D397D05B63634A0D5EE501E7940CC07315C0B8D14A39CE30CB2C17B2C36DFF4F4447762F2293C18D623D655FBF9803A6AFE9241884282061035538C1539190747CD8BB4ADDCBCDD07534F6DC65889307DC1FDE953D4F9E2AB0B0071AB75DAE4E30B59DD4C13040FC830849EB140C0FE7B5B930D966124FFD5989E15E3D6D9B50B03348C86F5EC7BF943D259A9D8A8DF0D2FADA33CC0BFA73D18C48A80F13F1B02EABC868D217EF9423C6AF01FD601E19CE377E3699CCF52415E48C")
	taggedBroadcast := new(obj.TaggedBroadcast)
	err = taggedBroadcast.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal("failed to decode broadcast, got error", err)
	}

	_, err = TryDecryptAndVerifyBroadcast(taggedBroadcast, addr)
	if err != nil {
		t.Errorf("failed to decrypt broadcast, got error %v", err)
	}

	// Test errors for TryDecryptAndVerifyBroadcast

	randId, _ := btcec.NewPrivateKey(btcec.S256())
	undecData, _ := btcec.Encrypt(PrivID1.Address.PrivateKey().PubKey(),
		[]byte{0x00, 0x00})
	validPubkey, _ := wire.NewPubKey(randId.PubKey().SerializeUncompressed()[1:])

	invSigningKey, invEncKey, forwardingData, invalidSig, mismatchSig := TstGenerateBroadcastErrorData(validPubkey)

	tests2 := []struct {
		broadcast obj.Broadcast
		address   *bmutil.Address
	}{

		// Invalid tag.
		{broadcast1.Object(), &PrivID2.Address},

		// Invalid address.
		{broadcast2.Object(), &PrivID2.Address},

		// Decryption failure.
		{obj.NewTaglessBroadcast(0, time.Now().Add(time.Minute*5), 1, []byte{0x00, 0x00}), &PrivID1.Address},

		// Undecodable decrypted data.
		{obj.NewTaggedBroadcast(0, time.Now().Add(time.Minute*5), 1, tag1, undecData), &PrivID1.Address},

		// Invalid embedded signing key.
		{obj.NewTaggedBroadcast(0, time.Now().Add(time.Minute*5), 1, tag1, invSigningKey), &PrivID1.Address},

		// Invalid embedded encryption key.
		{obj.NewTaggedBroadcast(0, time.Now().Add(time.Minute*5), 1, tag1, invEncKey), &PrivID1.Address},

		// Surreptitous forwarding attack.
		{obj.NewTaggedBroadcast(0, time.Now().Add(time.Minute*5), 1, tag1, forwardingData), &PrivID1.Address},

		// Invalid signature.
		{obj.NewTaggedBroadcast(0, time.Now().Add(time.Minute*5), 1, tag1, invalidSig), &PrivID1.Address},

		// Signature mismatch.
		{obj.NewTaggedBroadcast(0, time.Now().Add(time.Minute*5), 1, tag1, mismatchSig), &PrivID1.Address},
	}

	for i, test := range tests2 {
		if test.broadcast == nil {
			t.Fatalf("test case #%d is nil.", i)
		}
		_, err = TryDecryptAndVerifyBroadcast(test.broadcast, test.address)
		if err == nil {
			t.Errorf("for test case #%d didn't get error", i)
		}
	}
}

func TestMessages(t *testing.T) {

	// SignAndEncryptMsg
	destRipe, _ := hash.NewRipe(PrivID2.Address.Ripe[:])
	message, err := TstSignAndEncryptMessage(0, time.Now().Add(time.Minute*5).
		Truncate(time.Second), 1, nil, 4, 1, 1, SignKey1, EncKey1, 1000,
		1000, destRipe, 1, []byte("Hey there!"), []byte{}, nil, PrivID1, PrivID2.ToPublic())
	if err != nil {
		t.Errorf("for SignAndEncryptMsg got error %v", err)
	}

	// TryDecryptAndVerifyMsg

	var b bytes.Buffer
	msgObj := message.Object().MsgObject()
	msgObj.Encode(&b)

	msgTemp := new(obj.Message)
	msgTemp.Decode(bytes.NewReader(b.Bytes()))
	messageTemp, err := TryDecryptAndVerifyMessage(msgTemp, PrivID2)
	if err != nil {
		t.Errorf("for TryDecryptAndVerifyMessage got error %v", err)
	}
	if !reflect.DeepEqual(message, messageTemp) {
		t.Errorf("decrypted msg not the same as original, got %v want %v",
			messageTemp, message)
	}

	// Test actual message.
	data, _ := hex.DecodeString("0000000000A00248000000005586969C00000002010166738717DE363393847A60C36EF62E0B02CA002020D010226FDD506E7CA7601E35BD24DF39C97A292315D92BDF83C87F249C283F002022FECFC971D9828F6516D495FDD967CA0E36A7026637E30CCEF284F621546AF880C5C7FFF453B9195A23DF34645C6C347C4863655234577ADB6D684F7F5286C9ABCED249EFED1FA93EB7BAB68C791DC587F0B6821B9FE3FFFD525A40B1F9A77FBA4C1AD3C2DD7C292536161A12CA47AEB83ACFCF5F30EA82EE9CDDEE95A583901D3D48663F41A840BD20EE1F8E98B766C1583EE28D6ACC43CD174ADFBAC6C28FE1FDAFCE970E0F54A6D0C41DA6D68CA16846EFB5109E3B5B1F6FCF9F1DD466FB55F54C8423685ACCF3E5F6585C6A8F853B25F2603C1920216544610250F30B4E98C4501E6846CB44BFAFF509A1B9276045682FB2F9F08002D344298C3E38D7B260A41EF81352E3E180428BCABB1246394BDD2C238A96D5D9EC31ED121A8C3833D0BABB3C623169024B2DD592621C5109F2DF4BE130A0EDA4CB6D8147C00345CE84EEF29B5F548738E6F3BFAE36FEFE1B953BE89DDBD499F0AEC157FD96C372890465531357D3B337EAF500619E036DD8")
	msg := new(obj.Message)
	err = msg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal("failed to decode msg, got error", err)
	}

	_, err = TryDecryptAndVerifyMessage(msg, PrivID2)
	if err != nil {
		t.Errorf("failed to decrypt msg, got error %v", err)
	}

	// Test errors for TryDecryptAndVerifyMessage

	randId, _ := btcec.NewPrivateKey(btcec.S256())
	invPrivID, _ := btcec.Encrypt(randId.PubKey(), []byte{0x00, 0x00})
	undecData, _ := btcec.Encrypt(PrivID1.DecryptionKey.PubKey(),
		[]byte{0x00, 0x00})
	validPubkey, _ := wire.NewPubKey(randId.PubKey().SerializeUncompressed()[1:])

	invDest, invSigningKey, invalidSig, mismatchSig := TstGenerateMessageErrorData(validPubkey)

	tests2 := []struct {
		msg    *Message
		privId *identity.Private
	}{
		// Invalid private identity.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, invPrivID, 4, 1, 1, nil, nil, 1000, 1000,
			nil, 1, nil, nil, nil), PrivID1},

		// Decryption failure.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, []byte{0x00, 0x00}, 4, 1, 1, nil, nil, 1000, 1000, nil, 1,
			nil, nil, nil), PrivID1},

		// Undecodable decrypted data.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, undecData, 4, 1, 1, nil, nil, 1000, 1000, nil, 1,
			nil, nil, nil), PrivID1},

		// Invalid destination ripe.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, invDest, 4, 1, 1, nil, nil, 1000, 1000, nil, 1,
			nil, nil, nil), PrivID1},

		// Invalid embedded signing key.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, invSigningKey, 4, 1, 1, nil, nil, 1000, 1000, nil, 1,
			nil, nil, nil), PrivID1},

		// Invalid signature.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, invalidSig, 4, 1, 1, nil, nil, 1000, 1000, nil, 1,
			nil, nil, nil), PrivID1},

		// Signature mismatch.
		{TstNewMessage(0, time.Now().Add(time.Minute*5).Truncate(time.Second),
			1, mismatchSig, 4, 1, 1, nil, nil, 1000, 1000, nil, 1,
			nil, nil, nil), PrivID1},
	}

	for i, test := range tests2 {
		if test.msg == nil {
			t.Fatalf("test case #%d is nil.", i)
		}
		_, err = TryDecryptAndVerifyMessage(test.msg.Object(), test.privId)
		if err == nil {
			t.Errorf("for test case #%d didn't get error", i)
		}
	}
}
