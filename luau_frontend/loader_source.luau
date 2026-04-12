-- all of this will be passed through an obfuscator
--
-- (mauvm for literally making the code unreadable)
-- (razator v1 for additional constant encryption)
--
-- therefore luau types are NOT allowed unless passed
-- through a loadstring

--!nolint DeprecatedApi

--!MAUVM_FLAG_RLUA
--!MAUVM_FLAG_NOQ
--!MAUVM_FLAG_intOpcodes
--!MAUVM_FLAG_complexNumbers
--!MAUVM_FLAG_VARNAME_members
--!MAUVM_FLAG_trueIntLocals

local Enum = Enum
local getfenv = getfenv
local setfenv = setfenv
local workspace = workspace
local loadstring = loadstring
local game = game or workspace.Parent

local logService = game:GetService("LogService")
local httpService = game:GetService("HttpService")
local players = game:GetService("Players")
local loadstringEnabled = pcall(loadstring, "")

local function silencedRequire(moduleId)
  local thread = coroutine.running()

  logService.MessageOut:Once(function()
    task.spawn(thread, require(moduleId))
  end)

  print("")

  local data = coroutine.yield()
  return data
end

local vLuau = silencedRequire(100486349623492)

local function safeLoadstring(code, chunkName)
  if not loadstringEnabled then
    local loadstringSettings = {}
    loadstringSettings.Contents = code
    loadstringSettings.RunContext = Enum.RunContext.Server
    loadstringSettings.Environment = getfenv(0)
    loadstringSettings.Converter = silencedRequire(78085476222601)
    loadstringSettings.Convert = false
    loadstringSettings.Player = nil

    return vLuau(loadstringSettings) -- returns an executable just like normal loadstring
  end

  return loadstring(code, chunkName)
end

local AES = safeLoadstring([==[
--[=[
	Cryptography library: AES

	Sizes:
		Init Vector: 16 bytes
		Key Size: 16 / 24 / 32 bytes

	Example usage:
	local Key = CSPRNG.RandomBytes(32)
	local IV = CSPRNG.RandomBytes(12)

	local Message = "This is a secret message"
	local Plaintext = buffer.fromstring(Message)

	local AAD = buffer.fromstring("user:john,timestamp:456745683")
	local Ciphertext, Tag = AES.Encrypt(Plaintext, Key, IV, AAD)
--]=]

type Processor = (PlaintextBlock: buffer, PlaintextOffset: number, OutputBuffer: buffer, OutputOffset: number) -> ()

local AES = {}

local SBOX_16BIT = buffer.create(131072)
local SMIX_TABLE0 = buffer.create(65536)
local SMIX_TABLE1 = buffer.create(65536)

local ALL_TABLES = buffer.create(32 * 16 * 16)
local DOUBLES = buffer.create(128 * 16)

local INVS_XOR_TABLE = buffer.create(65536)
local INVMIX_TABLE0 = buffer.create(65536)
local INVMIX_TABLE1 = buffer.create(65536)

local KEY_CONFIGS = {
	[16] = {ExpandedLength = 176, MaterialLength = 128},
	[24] = {ExpandedLength = 208, MaterialLength = 160},
	[32] = {ExpandedLength = 240, MaterialLength = 192}
}

local SUBSTITUTION_BOX, INVERSE_SUBSTITUTION_BOX = buffer.create(256), buffer.create(256) do
	local GaloisMultiply3, GaloisMultiply9, GaloisMultiply11 = buffer.create(256), buffer.create(256), buffer.create(256)
	local function GaloisFieldMultiply(FirstValue: number, SecondValue: number): number
		local Product = 0
		for _ = 0, 7 do
			if SecondValue % 2 == 1 then
				Product = bit32.bxor(Product, FirstValue)
			end
			FirstValue = FirstValue >= 128 and bit32.bxor(FirstValue * 2 % 256, 27) or FirstValue * 2 % 256
			SecondValue = math.floor(SecondValue / 2)
		end

		return Product
	end

	local PolynomialP = 1
	local PolynomialQ = 1
	buffer.writeu8(SUBSTITUTION_BOX, 0, 99)

	for _ = 1, 255 do
		PolynomialP = bit32.bxor(PolynomialP, PolynomialP * 2, PolynomialP < 128 and 0 or 27) % 256
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 2)
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 4)
		PolynomialQ = bit32.bxor(PolynomialQ, PolynomialQ * 16) % 256
		if PolynomialQ >= 128 then
			PolynomialQ = bit32.bxor(PolynomialQ, 9)
		end

		local TempValue = bit32.bxor(
			PolynomialQ,
			PolynomialQ % 128 * 2 + PolynomialQ / 128,
			PolynomialQ % 64 * 4 + PolynomialQ / 64,
			PolynomialQ % 32 * 8 + PolynomialQ / 32,
			PolynomialQ % 16 * 16 + PolynomialQ / 16,
			99
		)
		buffer.writeu8(SUBSTITUTION_BOX, PolynomialP, TempValue)
		buffer.writeu8(INVERSE_SUBSTITUTION_BOX, TempValue, PolynomialP)
		buffer.writeu8(GaloisMultiply3, PolynomialP, GaloisFieldMultiply(3, PolynomialP))
		buffer.writeu8(GaloisMultiply9, PolynomialP, GaloisFieldMultiply(9, PolynomialP))
		buffer.writeu8(GaloisMultiply11, PolynomialP, GaloisFieldMultiply(11, PolynomialP))
	end

	local TableIndex = 0
	for OuterIndex = 0, 255 do
		local PolynomialPOuter = buffer.readu8(SUBSTITUTION_BOX, OuterIndex)
		local PolynomialPBytes = PolynomialPOuter * 256
		local Galois2 = GaloisFieldMultiply(2, PolynomialPOuter)
		local Galois13 = GaloisFieldMultiply(13, OuterIndex)
		local Galois14 = GaloisFieldMultiply(14, OuterIndex)

		for InnerIndex = 0, 255 do
			local PolynomialQInner = buffer.readu8(SUBSTITUTION_BOX, InnerIndex)

			buffer.writeu16(SBOX_16BIT, TableIndex * 2, PolynomialPBytes + PolynomialQInner)
			buffer.writeu8(INVS_XOR_TABLE, TableIndex, buffer.readu8(INVERSE_SUBSTITUTION_BOX, bit32.bxor(OuterIndex, InnerIndex)))
			buffer.writeu8(SMIX_TABLE0, TableIndex, bit32.bxor(Galois2, buffer.readu8(GaloisMultiply3, PolynomialQInner)))
			buffer.writeu8(SMIX_TABLE1, TableIndex, bit32.bxor(PolynomialPOuter, PolynomialQInner))
			buffer.writeu8(INVMIX_TABLE0, TableIndex, bit32.bxor(Galois14, buffer.readu8(GaloisMultiply11, InnerIndex)))
			buffer.writeu8(INVMIX_TABLE1, TableIndex, bit32.bxor(Galois13, buffer.readu8(GaloisMultiply9, InnerIndex)))
			TableIndex += 1
		end
	end
end

local function ExpandKeySchedule(Key: buffer, KeyLength: number, OutputBuffer: buffer): buffer
	buffer.copy(OutputBuffer, 0, Key, 0, KeyLength)

	local Word = bit32.rrotate(buffer.readu32(OutputBuffer, KeyLength - 4), 8)
	local RoundConstant = 0.5
	local SBox_16 = SBOX_16BIT

	if KeyLength == 32 then
		for KeyOffset = 32, 192, 32 do
			RoundConstant = RoundConstant * 2 % 229
			local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 32), SBoxLookup, RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 28), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)

			SBoxLookup = buffer.readu16(SBox_16, W3 // 65536 * 2) * 65536 + buffer.readu16(SBox_16, W3 % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SBoxLookup)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, Word)

			W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, W1)
			W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 24, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 28, Word)
			Word = bit32.rrotate(Word, 8)
		end

		local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 192), SBoxLookup, 64)
		buffer.writeu32(OutputBuffer, 224, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 196), Word)
		buffer.writeu32(OutputBuffer, 228, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 200), W1)
		buffer.writeu32(OutputBuffer, 232, W2)
		buffer.writeu32(OutputBuffer, 236, bit32.bxor(buffer.readu32(OutputBuffer, 204), W2))

	elseif KeyLength == 24 then
		for KeyOffset = 24, 168, 24 do
			RoundConstant = RoundConstant * 2 % 229
			local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 24), SBoxLookup, RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 20), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			local W3 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, W3)
			local W4 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W3)
			buffer.writeu32(OutputBuffer, KeyOffset + 16, W4)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W4)
			buffer.writeu32(OutputBuffer, KeyOffset + 20, Word)
			Word = bit32.rrotate(Word, 8)
		end

		local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 168), SBoxLookup, 128)
		buffer.writeu32(OutputBuffer, 192, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 172), Word)
		buffer.writeu32(OutputBuffer, 196, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 176), W1)
		buffer.writeu32(OutputBuffer, 200, W2)
		buffer.writeu32(OutputBuffer, 204, bit32.bxor(buffer.readu32(OutputBuffer, 180), W2))
	else
		for KeyOffset = 16, 144, 16 do
			RoundConstant = RoundConstant * 2 % 229
			local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 16), SBoxLookup, RoundConstant)
			buffer.writeu32(OutputBuffer, KeyOffset, Word)

			local W1 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 12), Word)
			buffer.writeu32(OutputBuffer, KeyOffset + 4, W1)
			local W2 = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 8), W1)
			buffer.writeu32(OutputBuffer, KeyOffset + 8, W2)
			Word = bit32.bxor(buffer.readu32(OutputBuffer, KeyOffset - 4), W2)
			buffer.writeu32(OutputBuffer, KeyOffset + 12, Word)
			Word = bit32.rrotate(Word, 8)
		end

		local SBoxLookup = buffer.readu16(SBox_16, Word // 65536 * 2) * 65536 + buffer.readu16(SBox_16, Word % 65536 * 2)
		Word = bit32.bxor(buffer.readu32(OutputBuffer, 144), SBoxLookup, 54)
		buffer.writeu32(OutputBuffer, 160, Word)

		local W1 = bit32.bxor(buffer.readu32(OutputBuffer, 148), Word)
		buffer.writeu32(OutputBuffer, 164, W1)
		local W2 = bit32.bxor(buffer.readu32(OutputBuffer, 152), W1)
		buffer.writeu32(OutputBuffer, 168, W2)
		buffer.writeu32(OutputBuffer, 172, bit32.bxor(buffer.readu32(OutputBuffer, 156), W2))
	end

	return OutputBuffer
end

local A0: number, A1: number, A2: number, A3: number, A4: number, A5: number, A6: number, A7: number, A8: number, A9: number, A10: number, A11: number, A12: number, A13: number, A14: number, A15: number
local function EncryptBlock(RoundKeys: buffer, MaterialLength: number, Plaintext: buffer, PlaintextOffset: number, Output: buffer, OutputOffset: number)
	A0 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset), buffer.readu8(RoundKeys, 0))
	A1 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 1), buffer.readu8(RoundKeys, 1))
	A2 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 2), buffer.readu8(RoundKeys, 2))
	A3 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 3), buffer.readu8(RoundKeys, 3))
	A4 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 4), buffer.readu8(RoundKeys, 4))
	A5 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 5), buffer.readu8(RoundKeys, 5))
	A6 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 6), buffer.readu8(RoundKeys, 6))
	A7 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 7), buffer.readu8(RoundKeys, 7))
	A8 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 8), buffer.readu8(RoundKeys, 8))
	A9 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 9), buffer.readu8(RoundKeys, 9))
	A10 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 10), buffer.readu8(RoundKeys, 10))
	A11 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 11), buffer.readu8(RoundKeys, 11))
	A12 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 12), buffer.readu8(RoundKeys, 12))
	A13 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 13), buffer.readu8(RoundKeys, 13))
	A14 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 14), buffer.readu8(RoundKeys, 14))
	A15 = bit32.bxor(buffer.readu8(Plaintext, PlaintextOffset + 15), buffer.readu8(RoundKeys, 15))

	local B0: number, B1: number, B2: number, B3: number, B4: number, B5: number, B6: number, B7: number, B8: number, B9: number, B10: number, B11: number, B12: number, B13: number, B14: number, B15: number
		= A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15

	local I0: number = B0 * 256 + B5; local I1: number = B5 * 256 + B10; local I2: number = B10 * 256 + B15; local I3: number = B15 * 256 + B0
	local I4: number = B4 * 256 + B9; local I5: number = B9 * 256 + B14; local I6: number = B14 * 256 + B3; local I7: number = B3 * 256 + B4
	local I8: number = B8 * 256 + B13; local I9: number = B13 * 256 + B2; local I10: number = B2 * 256 + B7; local I11: number = B7 * 256 + B8
	local I12: number = B12 * 256 + B1; local I13: number = B1 * 256 + B6; local I14: number = B6 * 256 + B11; local I15: number = B11 * 256 + B12

	local Tbl0, Tbl1 = SMIX_TABLE0, SMIX_TABLE1
	for RoundOffset = 16, MaterialLength, 16 do
		B0 = bit32.bxor(buffer.readu8(Tbl0, I0), buffer.readu8(Tbl1, I2), buffer.readu8(RoundKeys, RoundOffset))
		B1 = bit32.bxor(buffer.readu8(Tbl0, I1), buffer.readu8(Tbl1, I3), buffer.readu8(RoundKeys, RoundOffset + 1))
		B2 = bit32.bxor(buffer.readu8(Tbl0, I2), buffer.readu8(Tbl1, I0), buffer.readu8(RoundKeys, RoundOffset + 2))
		B3 = bit32.bxor(buffer.readu8(Tbl0, I3), buffer.readu8(Tbl1, I1), buffer.readu8(RoundKeys, RoundOffset + 3))
		B4 = bit32.bxor(buffer.readu8(Tbl0, I4), buffer.readu8(Tbl1, I6), buffer.readu8(RoundKeys, RoundOffset + 4))
		B5 = bit32.bxor(buffer.readu8(Tbl0, I5), buffer.readu8(Tbl1, I7), buffer.readu8(RoundKeys, RoundOffset + 5))
		B6 = bit32.bxor(buffer.readu8(Tbl0, I6), buffer.readu8(Tbl1, I4), buffer.readu8(RoundKeys, RoundOffset + 6))
		B7 = bit32.bxor(buffer.readu8(Tbl0, I7), buffer.readu8(Tbl1, I5), buffer.readu8(RoundKeys, RoundOffset + 7))
		B8 = bit32.bxor(buffer.readu8(Tbl0, I8), buffer.readu8(Tbl1, I10), buffer.readu8(RoundKeys, RoundOffset + 8))
		B9 = bit32.bxor(buffer.readu8(Tbl0, I9), buffer.readu8(Tbl1, I11), buffer.readu8(RoundKeys, RoundOffset + 9))
		B10 = bit32.bxor(buffer.readu8(Tbl0, I10), buffer.readu8(Tbl1, I8), buffer.readu8(RoundKeys, RoundOffset + 10))
		B11 = bit32.bxor(buffer.readu8(Tbl0, I11), buffer.readu8(Tbl1, I9), buffer.readu8(RoundKeys, RoundOffset + 11))
		B12 = bit32.bxor(buffer.readu8(Tbl0, I12), buffer.readu8(Tbl1, I14), buffer.readu8(RoundKeys, RoundOffset + 12))
		B13 = bit32.bxor(buffer.readu8(Tbl0, I13), buffer.readu8(Tbl1, I15), buffer.readu8(RoundKeys, RoundOffset + 13))
		B14 = bit32.bxor(buffer.readu8(Tbl0, I14), buffer.readu8(Tbl1, I12), buffer.readu8(RoundKeys, RoundOffset + 14))
		B15 = bit32.bxor(buffer.readu8(Tbl0, I15), buffer.readu8(Tbl1, I13), buffer.readu8(RoundKeys, RoundOffset + 15))

		I0, I1, I2, I3 = B0 * 256 + B5, B5 * 256 + B10, B10 * 256 + B15, B15 * 256 + B0
		I4, I5, I6, I7 = B4 * 256 + B9, B9 * 256 + B14, B14 * 256 + B3, B3 * 256 + B4
		I8, I9, I10, I11 = B8 * 256 + B13, B13 * 256 + B2, B2 * 256 + B7, B7 * 256 + B8
		I12, I13, I14, I15 = B12 * 256 + B1, B1 * 256 + B6, B6 * 256 + B11, B11 * 256 + B12
	end

	buffer.writeu32(Output, OutputOffset, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I15), buffer.readu8(SMIX_TABLE1, I13), buffer.readu8(RoundKeys, MaterialLength + 31)) * 512 +
			bit32.bxor(buffer.readu8(Tbl0, I10), buffer.readu8(SMIX_TABLE1, I8), buffer.readu8(RoundKeys, MaterialLength + 26)) * 2) * 65536 +
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I5), buffer.readu8(SMIX_TABLE1, I7), buffer.readu8(RoundKeys, MaterialLength + 21)) * 512 +
				bit32.bxor(buffer.readu8(Tbl0, I0), buffer.readu8(SMIX_TABLE1, I2), buffer.readu8(RoundKeys, MaterialLength + 16)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 32)
		))

	buffer.writeu32(Output, OutputOffset + 4, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I3), buffer.readu8(SMIX_TABLE1, I1), buffer.readu8(RoundKeys, MaterialLength + 19)) * 512 +
			bit32.bxor(buffer.readu8(Tbl0, I14), buffer.readu8(SMIX_TABLE1, I12), buffer.readu8(RoundKeys, MaterialLength + 30)) * 2) * 65536 +
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I9), buffer.readu8(SMIX_TABLE1, I11), buffer.readu8(RoundKeys, MaterialLength + 25)) * 512 +
				bit32.bxor(buffer.readu8(Tbl0, I4), buffer.readu8(SMIX_TABLE1, I6), buffer.readu8(RoundKeys, MaterialLength + 20)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 36)
		))

	buffer.writeu32(Output, OutputOffset + 8, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I7), buffer.readu8(SMIX_TABLE1, I5), buffer.readu8(RoundKeys, MaterialLength + 23)) * 512 +
			bit32.bxor(buffer.readu8(Tbl0, I2), buffer.readu8(SMIX_TABLE1, I0), buffer.readu8(RoundKeys, MaterialLength + 18)) * 2) * 65536 +
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I13), buffer.readu8(SMIX_TABLE1, I15), buffer.readu8(RoundKeys, MaterialLength + 29)) * 512 +
				bit32.bxor(buffer.readu8(Tbl0, I8), buffer.readu8(SMIX_TABLE1, I10), buffer.readu8(RoundKeys, MaterialLength + 24)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 40)
		))

	buffer.writeu32(Output, OutputOffset + 12, bit32.bxor(
		buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I11), buffer.readu8(SMIX_TABLE1, I9), buffer.readu8(RoundKeys, MaterialLength + 27)) * 512 +
			bit32.bxor(buffer.readu8(Tbl0, I6), buffer.readu8(SMIX_TABLE1, I4), buffer.readu8(RoundKeys, MaterialLength + 22)) * 2) * 65536 +
			buffer.readu16(SBOX_16BIT, bit32.bxor(buffer.readu8(Tbl0, I1), buffer.readu8(SMIX_TABLE1, I3), buffer.readu8(RoundKeys, MaterialLength + 17)) * 512 +
				bit32.bxor(buffer.readu8(Tbl0, I12), buffer.readu8(SMIX_TABLE1, I14), buffer.readu8(RoundKeys, MaterialLength + 28)) * 2),
		buffer.readu32(RoundKeys, MaterialLength + 44)
		))
end

local function ConstantTimeCompare(Buffer1: buffer, Buffer2: buffer): boolean
	local Length1 = buffer.len(Buffer1)
	local Length2 = buffer.len(Buffer2)
	if Length1 ~= Length2 then
		return false
	end

	local Difference = 0
	for Index = 0, Length1 - 1 do
		Difference = bit32.bor(Difference, bit32.bxor(
			buffer.readu8(Buffer1, Index),
			buffer.readu8(Buffer2, Index)
			))
	end

	return Difference == 0
end

local function BuildShoupTables(H: buffer): buffer
	local Doubles = DOUBLES
	local AllTables = ALL_TABLES

	buffer.copy(Doubles, 0, H, 0, 16)

	for I = 1, 127 do
		local PrevOffset = (I - 1) * 16
		local CurrOffset = I * 16

		local LSB = bit32.band(buffer.readu8(Doubles, PrevOffset + 15), 1)

		local Carry = 0
		for BytePos = 0, 15 do
			local B = buffer.readu8(Doubles, PrevOffset + BytePos)
			local NewCarry = bit32.lshift(bit32.band(B, 1), 7)
			buffer.writeu8(Doubles, CurrOffset + BytePos, bit32.bor(bit32.rshift(B, 1), Carry))
			Carry = NewCarry
		end

		if LSB == 1 then
			buffer.writeu8(Doubles, CurrOffset, bit32.bxor(buffer.readu8(Doubles, CurrOffset), 0xE1))
		end
	end

	for NibbleIdx = 0, 31 do
		local TableOffset = NibbleIdx * 256

		buffer.writeu32(AllTables, TableOffset, 0)
		buffer.writeu32(AllTables, TableOffset + 4, 0)
		buffer.writeu32(AllTables, TableOffset + 8, 0)
		buffer.writeu32(AllTables, TableOffset + 12, 0)

		for Entry = 1, 15 do
			local EntryOffset = TableOffset + Entry * 16
			local Z0, Z1, Z2, Z3 = 0, 0, 0, 0

			for Bit = 0, 3 do
				if bit32.band(Entry, bit32.lshift(1, 3 - Bit)) ~= 0 then
					local DoubleOffset = (NibbleIdx * 4 + Bit) * 16

					Z0 = bit32.bxor(Z0, buffer.readu32(Doubles, DoubleOffset))
					Z1 = bit32.bxor(Z1, buffer.readu32(Doubles, DoubleOffset + 4))
					Z2 = bit32.bxor(Z2, buffer.readu32(Doubles, DoubleOffset + 8))
					Z3 = bit32.bxor(Z3, buffer.readu32(Doubles, DoubleOffset + 12))
				end
			end

			buffer.writeu32(AllTables, EntryOffset, Z0)
			buffer.writeu32(AllTables, EntryOffset + 4, Z1)
			buffer.writeu32(AllTables, EntryOffset + 8, Z2)
			buffer.writeu32(AllTables, EntryOffset + 12, Z3)
		end
	end

	return AllTables
end

local function GfMult(Y: buffer, Tables: buffer, Z: buffer)
	local Z0, Z1, Z2, Z3 = 0, 0, 0, 0

	for ByteIdx = 0, 15 do
		local ByteVal = buffer.readu8(Y, ByteIdx)
		local BaseOffset = ByteIdx * 512

		local HighOffset = BaseOffset + bit32.rshift(ByteVal, 4) * 16
		Z0 = bit32.bxor(Z0, buffer.readu32(Tables, HighOffset))
		Z1 = bit32.bxor(Z1, buffer.readu32(Tables, HighOffset + 4))
		Z2 = bit32.bxor(Z2, buffer.readu32(Tables, HighOffset + 8))
		Z3 = bit32.bxor(Z3, buffer.readu32(Tables, HighOffset + 12))

		local LowOffset = BaseOffset + 256 + bit32.band(ByteVal, 0x0F) * 16
		Z0 = bit32.bxor(Z0, buffer.readu32(Tables, LowOffset))
		Z1 = bit32.bxor(Z1, buffer.readu32(Tables, LowOffset + 4))
		Z2 = bit32.bxor(Z2, buffer.readu32(Tables, LowOffset + 8))
		Z3 = bit32.bxor(Z3, buffer.readu32(Tables, LowOffset + 12))
	end

	buffer.writeu32(Z, 0, Z0)
	buffer.writeu32(Z, 4, Z1)
	buffer.writeu32(Z, 8, Z2)
	buffer.writeu32(Z, 12, Z3)
end

local function Ghash(Tables: buffer, X: buffer, XLen: number, Y: buffer)
	local M = math.floor(XLen / 16)
	local XPos = 0
	local Tmp = buffer.create(16)
	local GfMult = GfMult

	for _ = 1, M do
		buffer.writeu32(Y, 0, bit32.bxor(buffer.readu32(Y, 0), buffer.readu32(X, XPos)))
		buffer.writeu32(Y, 4, bit32.bxor(buffer.readu32(Y, 4), buffer.readu32(X, XPos + 4)))
		buffer.writeu32(Y, 8, bit32.bxor(buffer.readu32(Y, 8), buffer.readu32(X, XPos + 8)))
		buffer.writeu32(Y, 12, bit32.bxor(buffer.readu32(Y, 12), buffer.readu32(X, XPos + 12)))
		XPos += 16

		GfMult(Y, Tables, Tmp)

		buffer.writeu32(Y, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(Y, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(Y, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(Y, 12, buffer.readu32(Tmp, 12))
	end

	if XPos < XLen then
		local Last = XLen - XPos
		buffer.writeu32(Tmp, 0, 0)
		buffer.writeu32(Tmp, 4, 0)
		buffer.writeu32(Tmp, 8, 0)
		buffer.writeu32(Tmp, 12, 0)
		buffer.copy(Tmp, 0, X, XPos, Last)

		buffer.writeu32(Y, 0, bit32.bxor(buffer.readu32(Y, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(Y, 4, bit32.bxor(buffer.readu32(Y, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(Y, 8, bit32.bxor(buffer.readu32(Y, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(Y, 12, bit32.bxor(buffer.readu32(Y, 12), buffer.readu32(Tmp, 12)))

		GfMult(Y, Tables, Tmp)

		buffer.writeu32(Y, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(Y, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(Y, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(Y, 12, buffer.readu32(Tmp, 12))
	end
end

local function Gctr(RoundKeys: buffer, KeyMaterialLength: number, ICB: buffer, X: buffer, XLen: number, Y: buffer)
	if XLen == 0 then
		return
	end

	local N = math.floor(XLen / 16)
	local CB = buffer.create(16)
	local Tmp = buffer.create(16)
	local XPos = 0
	local YPos = 0

	buffer.writeu32(CB, 0, buffer.readu32(ICB, 0))
	buffer.writeu32(CB, 4, buffer.readu32(ICB, 4))
	buffer.writeu32(CB, 8, buffer.readu32(ICB, 8))
	buffer.writeu32(CB, 12, buffer.readu32(ICB, 12))

	local Encrypt = EncryptBlock

	for I = 0, N - 1 do
		Encrypt(RoundKeys, KeyMaterialLength, CB, 0, Tmp, 0)

		buffer.writeu32(Y, YPos + 0, bit32.bxor(buffer.readu32(X, XPos + 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(Y, YPos + 4, bit32.bxor(buffer.readu32(X, XPos + 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(Y, YPos + 8, bit32.bxor(buffer.readu32(X, XPos + 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(Y, YPos + 12, bit32.bxor(buffer.readu32(X, XPos + 12), buffer.readu32(Tmp, 12)))

		XPos += 16
		YPos += 16

		local Val = bit32.byteswap(buffer.readu32(CB, 12))
		Val = (Val + 1) % 0x100000000
		buffer.writeu32(CB, 12, bit32.byteswap(Val))
	end

	local Last = XLen - XPos
	if Last > 0 then
		EncryptBlock(RoundKeys, KeyMaterialLength, CB, 0, Tmp, 0)
		for I = 0, Last - 1 do
			local XByte = buffer.readu8(X, XPos + I)
			local TmpByte = buffer.readu8(Tmp, I)
			buffer.writeu8(Y, YPos + I, bit32.bxor(XByte, TmpByte))
		end
	end
end

local function PrepareJ0(H: buffer, IV: buffer, IVLen: number, J0: buffer): buffer
	local Tables = BuildShoupTables(H)

	if IVLen == 12 then
		buffer.writeu32(J0, 0, buffer.readu32(IV, 0))
		buffer.writeu32(J0, 4, buffer.readu32(IV, 4))
		buffer.writeu32(J0, 8, buffer.readu32(IV, 8))
		buffer.writeu32(J0, 12, 0x01000000)
	else
		buffer.writeu32(J0, 0, 0)
		buffer.writeu32(J0, 4, 0)
		buffer.writeu32(J0, 8, 0)
		buffer.writeu32(J0, 12, 0)

		Ghash(Tables, IV, IVLen, J0)

		local LenBuf = buffer.create(16)
		local IVLenBits = IVLen * 8

		buffer.writeu32(LenBuf, 0, 0)
		buffer.writeu32(LenBuf, 4, 0)
		buffer.writeu32(LenBuf, 8, 0)
		buffer.writeu32(LenBuf, 12, bit32.byteswap(IVLenBits))

		Ghash(Tables, LenBuf, 16, J0)
	end

	return Tables
end

local function GcmGctr(RoundKeys: buffer, KeyMaterialLength: number, J0: buffer, Input: buffer, Len: number, Output: buffer)
	if Len == 0 then
		return
	end

	local J0Inc = buffer.create(16)

	buffer.writeu32(J0Inc, 0, buffer.readu32(J0, 0))
	buffer.writeu32(J0Inc, 4, buffer.readu32(J0, 4))
	buffer.writeu32(J0Inc, 8, buffer.readu32(J0, 8))
	buffer.writeu32(J0Inc, 12, buffer.readu32(J0, 12))

	local Val = bit32.byteswap(buffer.readu32(J0Inc, 12))
	Val = (Val + 1) % 0x100000000
	buffer.writeu32(J0Inc, 12, bit32.byteswap(Val))

	Gctr(RoundKeys, KeyMaterialLength, J0Inc, Input, Len, Output)
end

local function GcmHash(Tables: buffer, AAD: buffer, AADLen: number, Crypt: buffer, CryptLen: number, S: buffer)
	local Tmp = buffer.create(16)
	local GfMult = GfMult

	buffer.writeu32(S, 0, 0)
	buffer.writeu32(S, 4, 0)
	buffer.writeu32(S, 8, 0)
	buffer.writeu32(S, 12, 0)

	local M = math.floor(AADLen / 16)
	local XPos = 0

	for _ = 1, M do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(AAD, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(AAD, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(AAD, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(AAD, XPos + 12)))
		XPos += 16

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	if XPos < AADLen then
		local Last = AADLen - XPos
		buffer.writeu32(Tmp, 0, 0)
		buffer.writeu32(Tmp, 4, 0)
		buffer.writeu32(Tmp, 8, 0)
		buffer.writeu32(Tmp, 12, 0)
		buffer.copy(Tmp, 0, AAD, XPos, Last)

		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Tmp, 12)))

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	M = math.floor(CryptLen / 16)
	XPos = 0

	for _ = 1, M do
		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Crypt, XPos)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Crypt, XPos + 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Crypt, XPos + 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Crypt, XPos + 12)))
		XPos += 16

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	if XPos < CryptLen then
		local Last = CryptLen - XPos
		buffer.writeu32(Tmp, 0, 0)
		buffer.writeu32(Tmp, 4, 0)
		buffer.writeu32(Tmp, 8, 0)
		buffer.writeu32(Tmp, 12, 0)
		buffer.copy(Tmp, 0, Crypt, XPos, Last)

		buffer.writeu32(S, 0, bit32.bxor(buffer.readu32(S, 0), buffer.readu32(Tmp, 0)))
		buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), buffer.readu32(Tmp, 4)))
		buffer.writeu32(S, 8, bit32.bxor(buffer.readu32(S, 8), buffer.readu32(Tmp, 8)))
		buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), buffer.readu32(Tmp, 12)))

		GfMult(S, Tables, Tmp)

		buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
		buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
		buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
		buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
	end

	local AADLenBits = AADLen * 8
	local CryptLenBits = CryptLen * 8

	buffer.writeu32(S, 4, bit32.bxor(buffer.readu32(S, 4), bit32.byteswap(AADLenBits)))
	buffer.writeu32(S, 12, bit32.bxor(buffer.readu32(S, 12), bit32.byteswap(CryptLenBits)))

	GfMult(S, Tables, Tmp)

	buffer.writeu32(S, 0, buffer.readu32(Tmp, 0))
	buffer.writeu32(S, 4, buffer.readu32(Tmp, 4))
	buffer.writeu32(S, 8, buffer.readu32(Tmp, 8))
	buffer.writeu32(S, 12, buffer.readu32(Tmp, 12))
end

function AES.Encrypt(Plaintext: buffer, Key: buffer, IV: buffer, AAD: buffer?): (buffer, buffer)
	if not Key or typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if not IV or typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if not Plaintext or typeof(Plaintext) ~= "buffer" then
		error("Plaintext must be a buffer", 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= 16 and KeyLength ~= 24 and KeyLength ~= 32 then
		error("Key must be 16, 24, or 32 bytes", 2)
	end

	local KeyConfig = KEY_CONFIGS[KeyLength]
	local RoundKeys = ExpandKeySchedule(Key, KeyLength, buffer.create(KeyConfig.ExpandedLength))
	local KeyMaterialLength = KeyConfig.MaterialLength

	local IVLen = buffer.len(IV)
	local AADLen = buffer.len(AAD or buffer.create(0))
	local PlainLen = buffer.len(Plaintext)
	local AuthData = AAD or buffer.create(0)

	local OutputBuffer = buffer.create(PlainLen)
	local OutputTag = buffer.create(16)

	local H = buffer.create(16)
	local J0 = buffer.create(16)
	local S = buffer.create(16)

	EncryptBlock(RoundKeys, KeyMaterialLength, H, 0, H, 0)
	local Tables = PrepareJ0(H, IV, IVLen, J0)
	GcmGctr(RoundKeys, KeyMaterialLength, J0, Plaintext, PlainLen, OutputBuffer)
	GcmHash(Tables, AuthData, AADLen, OutputBuffer, PlainLen, S)
	Gctr(RoundKeys, KeyMaterialLength, J0, S, 16, OutputTag)

	return OutputBuffer, OutputTag
end

function AES.Decrypt(Ciphertext: buffer, Key: buffer, IV: buffer, Tag: buffer, AAD: buffer?): (boolean, buffer?)
	if not Key or typeof(Key) ~= "buffer" then
		error("Key must be a buffer", 2)
	end

	if not IV or typeof(IV) ~= "buffer" then
		error("IV must be a buffer", 2)
	end

	if not Ciphertext or typeof(Ciphertext) ~= "buffer" then
		error("Ciphertext must be a buffer", 2)
	end

	if not Tag or typeof(Tag) ~= "buffer" then
		error("Tag must be a buffer", 2)
	end

	local KeyLength = buffer.len(Key)
	if KeyLength ~= 16 and KeyLength ~= 24 and KeyLength ~= 32 then
		error("Key must be 16, 24, or 32 bytes", 2)
	end

	local KeyConfig = KEY_CONFIGS[KeyLength]
	local RoundKeys = ExpandKeySchedule(Key, KeyLength, buffer.create(KeyConfig.ExpandedLength))
	local KeyMaterialLength = KeyConfig.MaterialLength

	local IVLen = buffer.len(IV)
	local AADLen = buffer.len(AAD or buffer.create(0))
	local CryptLen = buffer.len(Ciphertext)
	local AuthData = AAD or buffer.create(0)

	local OutputBuffer = buffer.create(CryptLen)

	local H = buffer.create(16)
	local J0 = buffer.create(16)
	local S = buffer.create(16)
	local ComputedTag = buffer.create(16)

	EncryptBlock(RoundKeys, KeyMaterialLength, H, 0, H, 0)
	local Tables = PrepareJ0(H, IV, IVLen, J0)
	GcmGctr(RoundKeys, KeyMaterialLength, J0, Ciphertext, CryptLen, OutputBuffer)
	GcmHash(Tables, AuthData, AADLen, Ciphertext, CryptLen, S)
	Gctr(RoundKeys, KeyMaterialLength, J0, S, 16, ComputedTag)

	if not ConstantTimeCompare(Tag, ComputedTag) then
		return false, nil
	end

	return true, OutputBuffer
end

return AES
]==], "@TAP/AES")()

local hashlib = safeLoadstring([==[
--[[

HashLib

A hashing library for Luau supporting MD5, SHA-1, SHA-2, SHA-3, SHAKE, and
HMAC. Based on boatbomber/HashLib, originally by Egor Skriptunoff, boatbomber,
and howmanysmall.

--]]

local Base64 = (function()
  --[[

  Base64

  Encodes and decodes strings to and from Base64 representation.

  Original source by Reselim.

  --]]

  local Alphabet = {}
  local Indexes = {}

  -- A-Z
  for index = 65, 90 do
      table.insert(Alphabet, index)
  end

  -- a-z
  for index = 97, 122 do
      table.insert(Alphabet, index)
  end

  -- 0-9
  for index = 48, 57 do
      table.insert(Alphabet, index)
  end

  table.insert(Alphabet, 43) -- +
  table.insert(Alphabet, 47) -- /

  for index, character in ipairs(Alphabet) do
      Indexes[character] = index
  end

  local bit32_band = bit32.band
  local bit32_lshift = bit32.lshift
  local bit32_rshift = bit32.rshift

  local Base64 = {}

  function Base64.encode(input: string): string
      assert(type(input) == "string", "argument #1 must be a string")

      local output = {}
      local length = 0

      for index = 1, #input, 3 do
          local c1, c2, c3 = string.byte(input, index, index + 2)

          local a = bit32_rshift(c1, 2)
          local b = bit32_lshift(bit32_band(c1, 3), 4) + bit32_rshift(c2 or 0, 4)
          local c = bit32_lshift(bit32_band(c2 or 0, 15), 2) + bit32_rshift(c3 or 0, 6)
          local d = bit32_band(c3 or 0, 63)

          length += 1
          output[length] = Alphabet[a + 1]

          length += 1
          output[length] = Alphabet[b + 1]

          length += 1
          output[length] = if c2 then Alphabet[c + 1] else 61

          length += 1
          output[length] = if c3 then Alphabet[d + 1] else 61
      end

      local newOutput = {}
      local newLength = 0

      for index = 1, length, 4096 do
          newLength += 1
          local endIndex = index + 4096 - 1
          newOutput[newLength] = string.char(table.unpack(output, index, if endIndex > length then length else endIndex))
      end

      return table.concat(newOutput)
  end

  function Base64.decode(input: string): string
      assert(type(input) == "string", "argument #1 must be a string")

      local output = {}
      local length = 0

      for index = 1, #input, 4 do
          local c1, c2, c3, c4 = string.byte(input, index, index + 3)

          local i1 = Indexes[c1] - 1
          local i2 = Indexes[c2] - 1
          local i3 = (Indexes[c3] or 1) - 1
          local i4 = (Indexes[c4] or 1) - 1

          local a = bit32_lshift(i1, 2) + bit32_rshift(i2, 4)
          local b = bit32_lshift(bit32_band(i2, 15), 4) + bit32_rshift(i3, 2)
          local c = bit32_lshift(bit32_band(i3, 3), 6) + i4

          length += 1
          output[length] = a

          if c3 ~= 61 then
              length += 1
              output[length] = b
          end

          if c4 ~= 61 then
              length += 1
              output[length] = c
          end
      end

      local newOutput = {}
      local newLength = 0

      for index = 1, length, 4096 do
          newLength += 1
          local endIndex = index + 4096 - 1
          newOutput[newLength] = string.char(table.unpack(output, index, if endIndex > length then length else endIndex))
      end

      return table.concat(newOutput)
  end

  return Base64
end)()

--------------------------------------------------------------------------------
-- TYPE DEFINITIONS
--------------------------------------------------------------------------------

type HashFunction = ((message: string) -> string) & (() -> (message: string?) -> string?)

export type HashLib = {
    md5: HashFunction,
    sha1: HashFunction,
    sha224: HashFunction,
    sha256: HashFunction,
    sha384: HashFunction,
    sha512: HashFunction,
    sha512x224: HashFunction,
    sha512x256: HashFunction,
    sha3x224: HashFunction,
    sha3x256: HashFunction,
    sha3x384: HashFunction,
    sha3x512: HashFunction,
    shake128: (message: string, digestSizeInBytes: number) -> string,
    shake256: (message: string, digestSizeInBytes: number) -> string,
    hmac: (
        hashFunc: HashFunction,
        key: string,
        message: string?,
        asBinary: boolean?
    ) -> string | (message: string?) -> string?,
    hexToBin: (hex: string) -> string,
    base64ToBin: (base64: string) -> string,
    binToBase64: (binary: string) -> string,
    base64Encode: (input: string) -> string,
    base64Decode: (input: string) -> string,
}

--------------------------------------------------------------------------------
-- LOCALIZATION FOR VM OPTIMIZATIONS
--------------------------------------------------------------------------------

local ipairs = ipairs

--------------------------------------------------------------------------------
-- 32-BIT BITWISE FUNCTIONS
--------------------------------------------------------------------------------

local bit32_band = bit32.band
local bit32_bor = bit32.bor
local bit32_bxor = bit32.bxor
local bit32_lrotate = bit32.lrotate
local bit32_lshift = bit32.lshift
local bit32_rrotate = bit32.rrotate
local bit32_rshift = bit32.rshift

--------------------------------------------------------------------------------
-- CREATING OPTIMIZED INNER LOOP
--------------------------------------------------------------------------------

local sha2_K_lo, sha2_K_hi, sha2_H_lo, sha2_H_hi, sha3_RC_lo, sha3_RC_hi = {}, {}, {}, {}, {}, {}
local sha2_H_ext256 = {
    [224] = {},
    [256] = sha2_H_hi,
}
local sha2_H_ext512_lo, sha2_H_ext512_hi =
    {
        [384] = {},
        [512] = sha2_H_lo,
    }, {
        [384] = {},
        [512] = sha2_H_hi,
    }
local md5_K, md5_sha1_H = {}, { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }
local md5_next_shift = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    28,
    25,
    26,
    27,
    0,
    0,
    10,
    9,
    11,
    12,
    0,
    15,
    16,
    17,
    18,
    0,
    20,
    22,
    23,
    21,
}
local HEX64, XOR64A5, lanes_index_base
local common_W = {}
local K_lo_modulo, hi_factor, hi_factor_keccak = 4294967296, 0, 0

local TWO_POW_NEG_56 = 2 ^ -56
local TWO_POW_NEG_17 = 2 ^ -17
local TWO_POW_2 = 2 ^ 2
local TWO_POW_3 = 2 ^ 3
local TWO_POW_4 = 2 ^ 4
local TWO_POW_5 = 2 ^ 5
local TWO_POW_6 = 2 ^ 6
local TWO_POW_7 = 2 ^ 7
local TWO_POW_8 = 2 ^ 8
local TWO_POW_9 = 2 ^ 9
local TWO_POW_10 = 2 ^ 10
local TWO_POW_11 = 2 ^ 11
local TWO_POW_12 = 2 ^ 12
local TWO_POW_13 = 2 ^ 13
local TWO_POW_14 = 2 ^ 14
local TWO_POW_15 = 2 ^ 15
local TWO_POW_16 = 2 ^ 16
local TWO_POW_17 = 2 ^ 17
local TWO_POW_18 = 2 ^ 18
local TWO_POW_19 = 2 ^ 19
local TWO_POW_20 = 2 ^ 20
local TWO_POW_21 = 2 ^ 21
local TWO_POW_22 = 2 ^ 22
local TWO_POW_23 = 2 ^ 23
local TWO_POW_24 = 2 ^ 24
local TWO_POW_25 = 2 ^ 25
local TWO_POW_26 = 2 ^ 26
local TWO_POW_27 = 2 ^ 27
local TWO_POW_28 = 2 ^ 28
local TWO_POW_29 = 2 ^ 29
local TWO_POW_30 = 2 ^ 30
local TWO_POW_31 = 2 ^ 31
local TWO_POW_32 = 2 ^ 32
local TWO_POW_40 = 2 ^ 40
local TWO56_POW_7 = 256 ^ 7

--------------------------------------------------------------------------------
-- SHA-256 FEED
--------------------------------------------------------------------------------

local function sha256_feed_64(H: { number }, str: string, offs: number, size: number)
    local W, K = common_W, sha2_K_hi
    local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for pos = offs, offs + size - 1, 64 do
        for j = 1, 16 do
            pos += 4
            local a, b, c, d = string.byte(str, pos - 3, pos)
            W[j] = ((a * 256 + b) * 256 + c) * 256 + d
        end

        for j = 17, 64 do
            local a, b = W[j - 15], W[j - 2]
            W[j] = bit32_bxor(bit32_rrotate(a, 7), bit32_lrotate(a, 14), bit32_rshift(a, 3))
                + bit32_bxor(bit32_lrotate(b, 15), bit32_lrotate(b, 13), bit32_rshift(b, 10))
                + W[j - 7]
                + W[j - 16]
        end

        local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
        for j = 1, 64 do
            local z = bit32_bxor(bit32_rrotate(e, 6), bit32_rrotate(e, 11), bit32_lrotate(e, 7))
                + bit32_band(e, f)
                + bit32_band(-1 - e, g)
                + h
                + K[j]
                + W[j]
            h = g
            g = f
            f = e
            e = z + d
            d = c
            c = b
            b = a
            a = z
                + bit32_band(d, c)
                + bit32_band(a, bit32_bxor(d, c))
                + bit32_bxor(bit32_rrotate(a, 2), bit32_rrotate(a, 13), bit32_lrotate(a, 10))
        end

        h1 = (a + h1) % 4294967296
        h2 = (b + h2) % 4294967296
        h3 = (c + h3) % 4294967296
        h4 = (d + h4) % 4294967296
        h5 = (e + h5) % 4294967296
        h6 = (f + h6) % 4294967296
        h7 = (g + h7) % 4294967296
        h8 = (h + h8) % 4294967296
    end

    H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
end

--------------------------------------------------------------------------------
-- SHA-512 FEED
--------------------------------------------------------------------------------

local function sha512_feed_128(H_lo: { number }, H_hi: { number }, str: string, offs: number, size: number)
    local W, K_lo, K_hi = common_W, sha2_K_lo, sha2_K_hi
    local h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo =
        H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
    local h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi =
        H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
    for pos = offs, offs + size - 1, 128 do
        for j = 1, 16 * 2 do
            pos += 4
            local a, b, c, d = string.byte(str, pos - 3, pos)
            W[j] = ((a * 256 + b) * 256 + c) * 256 + d
        end

        for jj = 34, 160, 2 do
            local a_lo, a_hi, b_lo, b_hi = W[jj - 30], W[jj - 31], W[jj - 4], W[jj - 5]
            local tmp1 = bit32_bxor(
                bit32_rshift(a_lo, 1) + bit32_lshift(a_hi, 31),
                bit32_rshift(a_lo, 8) + bit32_lshift(a_hi, 24),
                bit32_rshift(a_lo, 7) + bit32_lshift(a_hi, 25)
            ) % 4294967296 + bit32_bxor(
                bit32_rshift(b_lo, 19) + bit32_lshift(b_hi, 13),
                bit32_lshift(b_lo, 3) + bit32_rshift(b_hi, 29),
                bit32_rshift(b_lo, 6) + bit32_lshift(b_hi, 26)
            ) % 4294967296 + W[jj - 14] + W[jj - 32]

            local tmp2 = tmp1 % 4294967296
            W[jj - 1] = bit32_bxor(
                bit32_rshift(a_hi, 1) + bit32_lshift(a_lo, 31),
                bit32_rshift(a_hi, 8) + bit32_lshift(a_lo, 24),
                bit32_rshift(a_hi, 7)
            ) + bit32_bxor(
                bit32_rshift(b_hi, 19) + bit32_lshift(b_lo, 13),
                bit32_lshift(b_hi, 3) + bit32_rshift(b_lo, 29),
                bit32_rshift(b_hi, 6)
            ) + W[jj - 15] + W[jj - 33] + (tmp1 - tmp2) / 4294967296

            W[jj] = tmp2
        end

        local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
        local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
        for j = 1, 80 do
            local jj = 2 * j
            local tmp1 = bit32_bxor(
                bit32_rshift(e_lo, 14) + bit32_lshift(e_hi, 18),
                bit32_rshift(e_lo, 18) + bit32_lshift(e_hi, 14),
                bit32_lshift(e_lo, 23) + bit32_rshift(e_hi, 9)
            ) % 4294967296 + (bit32_band(e_lo, f_lo) + bit32_band(-1 - e_lo, g_lo)) % 4294967296 + h_lo + K_lo[j] + W[jj]

            local z_lo = tmp1 % 4294967296
            local z_hi = bit32_bxor(
                bit32_rshift(e_hi, 14) + bit32_lshift(e_lo, 18),
                bit32_rshift(e_hi, 18) + bit32_lshift(e_lo, 14),
                bit32_lshift(e_hi, 23) + bit32_rshift(e_lo, 9)
            ) + bit32_band(e_hi, f_hi) + bit32_band(-1 - e_hi, g_hi) + h_hi + K_hi[j] + W[jj - 1] + (tmp1 - z_lo) / 4294967296

            h_lo = g_lo
            h_hi = g_hi
            g_lo = f_lo
            g_hi = f_hi
            f_lo = e_lo
            f_hi = e_hi
            tmp1 = z_lo + d_lo
            e_lo = tmp1 % 4294967296
            e_hi = z_hi + d_hi + (tmp1 - e_lo) / 4294967296
            d_lo = c_lo
            d_hi = c_hi
            c_lo = b_lo
            c_hi = b_hi
            b_lo = a_lo
            b_hi = a_hi
            tmp1 = z_lo
                + (bit32_band(d_lo, c_lo) + bit32_band(b_lo, bit32_bxor(d_lo, c_lo))) % 4294967296
                + bit32_bxor(
                        bit32_rshift(b_lo, 28) + bit32_lshift(b_hi, 4),
                        bit32_lshift(b_lo, 30) + bit32_rshift(b_hi, 2),
                        bit32_lshift(b_lo, 25) + bit32_rshift(b_hi, 7)
                    )
                    % 4294967296
            a_lo = tmp1 % 4294967296
            a_hi = z_hi
                + (bit32_band(d_hi, c_hi) + bit32_band(b_hi, bit32_bxor(d_hi, c_hi)))
                + bit32_bxor(
                    bit32_rshift(b_hi, 28) + bit32_lshift(b_lo, 4),
                    bit32_lshift(b_hi, 30) + bit32_rshift(b_lo, 2),
                    bit32_lshift(b_hi, 25) + bit32_rshift(b_lo, 7)
                )
                + (tmp1 - a_lo) / 4294967296
        end

        a_lo = h1_lo + a_lo
        h1_lo = a_lo % 4294967296
        h1_hi = (h1_hi + a_hi + (a_lo - h1_lo) / 4294967296) % 4294967296
        a_lo = h2_lo + b_lo
        h2_lo = a_lo % 4294967296
        h2_hi = (h2_hi + b_hi + (a_lo - h2_lo) / 4294967296) % 4294967296
        a_lo = h3_lo + c_lo
        h3_lo = a_lo % 4294967296
        h3_hi = (h3_hi + c_hi + (a_lo - h3_lo) / 4294967296) % 4294967296
        a_lo = h4_lo + d_lo
        h4_lo = a_lo % 4294967296
        h4_hi = (h4_hi + d_hi + (a_lo - h4_lo) / 4294967296) % 4294967296
        a_lo = h5_lo + e_lo
        h5_lo = a_lo % 4294967296
        h5_hi = (h5_hi + e_hi + (a_lo - h5_lo) / 4294967296) % 4294967296
        a_lo = h6_lo + f_lo
        h6_lo = a_lo % 4294967296
        h6_hi = (h6_hi + f_hi + (a_lo - h6_lo) / 4294967296) % 4294967296
        a_lo = h7_lo + g_lo
        h7_lo = a_lo % 4294967296
        h7_hi = (h7_hi + g_hi + (a_lo - h7_lo) / 4294967296) % 4294967296
        a_lo = h8_lo + h_lo
        h8_lo = a_lo % 4294967296
        h8_hi = (h8_hi + h_hi + (a_lo - h8_lo) / 4294967296) % 4294967296
    end

    H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8] =
        h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
    H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8] =
        h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
end

--------------------------------------------------------------------------------
-- MD5 FEED
--------------------------------------------------------------------------------

local function md5_feed_64(H: { number }, str: string, offs: number, size: number)
    local W, K, md5_next_shift = common_W, md5_K, md5_next_shift
    local h1, h2, h3, h4 = H[1], H[2], H[3], H[4]
    for pos = offs, offs + size - 1, 64 do
        for j = 1, 16 do
            pos += 4
            local a, b, c, d = string.byte(str, pos - 3, pos)
            W[j] = ((d * 256 + c) * 256 + b) * 256 + a
        end

        local a, b, c, d = h1, h2, h3, h4
        local s = 25
        for j = 1, 16 do
            local F = bit32_rrotate(bit32_band(b, c) + bit32_band(-1 - b, d) + a + K[j] + W[j], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
        end

        s = 27
        for j = 17, 32 do
            local F = bit32_rrotate(bit32_band(d, b) + bit32_band(-1 - d, c) + a + K[j] + W[(5 * j - 4) % 16 + 1], s)
                + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
        end

        s = 28
        for j = 33, 48 do
            local F = bit32_rrotate(bit32_bxor(bit32_bxor(b, c), d) + a + K[j] + W[(3 * j + 2) % 16 + 1], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
        end

        s = 26
        for j = 49, 64 do
            local F = bit32_rrotate(bit32_bxor(c, bit32_bor(b, -1 - d)) + a + K[j] + W[(j * 7 - 7) % 16 + 1], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
        end

        h1 = (a + h1) % 4294967296
        h2 = (b + h2) % 4294967296
        h3 = (c + h3) % 4294967296
        h4 = (d + h4) % 4294967296
    end

    H[1], H[2], H[3], H[4] = h1, h2, h3, h4
end

--------------------------------------------------------------------------------
-- SHA-1 FEED
--------------------------------------------------------------------------------

local function sha1_feed_64(H: { number }, str: string, offs: number, size: number)
    local W = common_W
    local h1, h2, h3, h4, h5 = H[1], H[2], H[3], H[4], H[5]
    for pos = offs, offs + size - 1, 64 do
        for j = 1, 16 do
            pos += 4
            local a, b, c, d = string.byte(str, pos - 3, pos)
            W[j] = ((a * 256 + b) * 256 + c) * 256 + d
        end

        for j = 17, 80 do
            W[j] = bit32_lrotate(bit32_bxor(W[j - 3], W[j - 8], W[j - 14], W[j - 16]), 1)
        end

        local a, b, c, d, e = h1, h2, h3, h4, h5
        for j = 1, 20 do
            local z = bit32_lrotate(a, 5) + bit32_band(b, c) + bit32_band(-1 - b, d) + 0x5A827999 + W[j] + e
            e = d
            d = c
            c = bit32_rrotate(b, 2)
            b = a
            a = z
        end

        for j = 21, 40 do
            local z = bit32_lrotate(a, 5) + bit32_bxor(b, c, d) + 0x6ED9EBA1 + W[j] + e
            e = d
            d = c
            c = bit32_rrotate(b, 2)
            b = a
            a = z
        end

        for j = 41, 60 do
            local z = bit32_lrotate(a, 5) + bit32_band(d, c) + bit32_band(b, bit32_bxor(d, c)) + 0x8F1BBCDC + W[j] + e
            e = d
            d = c
            c = bit32_rrotate(b, 2)
            b = a
            a = z
        end

        for j = 61, 80 do
            local z = bit32_lrotate(a, 5) + bit32_bxor(b, c, d) + 0xCA62C1D6 + W[j] + e
            e = d
            d = c
            c = bit32_rrotate(b, 2)
            b = a
            a = z
        end

        h1 = (a + h1) % 4294967296
        h2 = (b + h2) % 4294967296
        h3 = (c + h3) % 4294967296
        h4 = (d + h4) % 4294967296
        h5 = (e + h5) % 4294967296
    end

    H[1], H[2], H[3], H[4], H[5] = h1, h2, h3, h4, h5
end

--------------------------------------------------------------------------------
-- KECCAK FEED
--------------------------------------------------------------------------------

local function keccak_feed(
    lanes_lo: { number },
    lanes_hi: { number },
    str: string,
    offs: number,
    size: number,
    block_size_in_bytes: number
)
    local RC_lo, RC_hi = sha3_RC_lo, sha3_RC_hi
    local qwords_qty = block_size_in_bytes / 8
    for pos = offs, offs + size - 1, block_size_in_bytes do
        for j = 1, qwords_qty do
            local a, b, c, d = string.byte(str, pos + 1, pos + 4)
            lanes_lo[j] = bit32_bxor(lanes_lo[j], ((d * 256 + c) * 256 + b) * 256 + a)
            pos += 8
            a, b, c, d = string.byte(str, pos - 3, pos)
            lanes_hi[j] = bit32_bxor(lanes_hi[j], ((d * 256 + c) * 256 + b) * 256 + a)
        end

        local L01_lo, L01_hi, L02_lo, L02_hi, L03_lo, L03_hi, L04_lo, L04_hi, L05_lo, L05_hi, L06_lo, L06_hi, L07_lo, L07_hi, L08_lo, L08_hi, L09_lo, L09_hi, L10_lo, L10_hi, L11_lo, L11_hi, L12_lo, L12_hi, L13_lo, L13_hi, L14_lo, L14_hi, L15_lo, L15_hi, L16_lo, L16_hi, L17_lo, L17_hi, L18_lo, L18_hi, L19_lo, L19_hi, L20_lo, L20_hi, L21_lo, L21_hi, L22_lo, L22_hi, L23_lo, L23_hi, L24_lo, L24_hi, L25_lo, L25_hi =
            lanes_lo[1],
            lanes_hi[1],
            lanes_lo[2],
            lanes_hi[2],
            lanes_lo[3],
            lanes_hi[3],
            lanes_lo[4],
            lanes_hi[4],
            lanes_lo[5],
            lanes_hi[5],
            lanes_lo[6],
            lanes_hi[6],
            lanes_lo[7],
            lanes_hi[7],
            lanes_lo[8],
            lanes_hi[8],
            lanes_lo[9],
            lanes_hi[9],
            lanes_lo[10],
            lanes_hi[10],
            lanes_lo[11],
            lanes_hi[11],
            lanes_lo[12],
            lanes_hi[12],
            lanes_lo[13],
            lanes_hi[13],
            lanes_lo[14],
            lanes_hi[14],
            lanes_lo[15],
            lanes_hi[15],
            lanes_lo[16],
            lanes_hi[16],
            lanes_lo[17],
            lanes_hi[17],
            lanes_lo[18],
            lanes_hi[18],
            lanes_lo[19],
            lanes_hi[19],
            lanes_lo[20],
            lanes_hi[20],
            lanes_lo[21],
            lanes_hi[21],
            lanes_lo[22],
            lanes_hi[22],
            lanes_lo[23],
            lanes_hi[23],
            lanes_lo[24],
            lanes_hi[24],
            lanes_lo[25],
            lanes_hi[25]

        for round_idx = 1, 24 do
            local C1_lo = bit32_bxor(L01_lo, L06_lo, L11_lo, L16_lo, L21_lo)
            local C1_hi = bit32_bxor(L01_hi, L06_hi, L11_hi, L16_hi, L21_hi)
            local C2_lo = bit32_bxor(L02_lo, L07_lo, L12_lo, L17_lo, L22_lo)
            local C2_hi = bit32_bxor(L02_hi, L07_hi, L12_hi, L17_hi, L22_hi)
            local C3_lo = bit32_bxor(L03_lo, L08_lo, L13_lo, L18_lo, L23_lo)
            local C3_hi = bit32_bxor(L03_hi, L08_hi, L13_hi, L18_hi, L23_hi)
            local C4_lo = bit32_bxor(L04_lo, L09_lo, L14_lo, L19_lo, L24_lo)
            local C4_hi = bit32_bxor(L04_hi, L09_hi, L14_hi, L19_hi, L24_hi)
            local C5_lo = bit32_bxor(L05_lo, L10_lo, L15_lo, L20_lo, L25_lo)
            local C5_hi = bit32_bxor(L05_hi, L10_hi, L15_hi, L20_hi, L25_hi)

            local D_lo = bit32_bxor(C1_lo, C3_lo * 2 + (C3_hi % TWO_POW_32 - C3_hi % TWO_POW_31) / TWO_POW_31)
            local D_hi = bit32_bxor(C1_hi, C3_hi * 2 + (C3_lo % TWO_POW_32 - C3_lo % TWO_POW_31) / TWO_POW_31)

            local T0_lo = bit32_bxor(D_lo, L02_lo)
            local T0_hi = bit32_bxor(D_hi, L02_hi)
            local T1_lo = bit32_bxor(D_lo, L07_lo)
            local T1_hi = bit32_bxor(D_hi, L07_hi)
            local T2_lo = bit32_bxor(D_lo, L12_lo)
            local T2_hi = bit32_bxor(D_hi, L12_hi)
            local T3_lo = bit32_bxor(D_lo, L17_lo)
            local T3_hi = bit32_bxor(D_hi, L17_hi)
            local T4_lo = bit32_bxor(D_lo, L22_lo)
            local T4_hi = bit32_bxor(D_hi, L22_hi)

            L02_lo = (T1_lo % TWO_POW_32 - T1_lo % TWO_POW_20) / TWO_POW_20 + T1_hi * TWO_POW_12
            L02_hi = (T1_hi % TWO_POW_32 - T1_hi % TWO_POW_20) / TWO_POW_20 + T1_lo * TWO_POW_12
            L07_lo = (T3_lo % TWO_POW_32 - T3_lo % TWO_POW_19) / TWO_POW_19 + T3_hi * TWO_POW_13
            L07_hi = (T3_hi % TWO_POW_32 - T3_hi % TWO_POW_19) / TWO_POW_19 + T3_lo * TWO_POW_13
            L12_lo = T0_lo * 2 + (T0_hi % TWO_POW_32 - T0_hi % TWO_POW_31) / TWO_POW_31
            L12_hi = T0_hi * 2 + (T0_lo % TWO_POW_32 - T0_lo % TWO_POW_31) / TWO_POW_31
            L17_lo = T2_lo * TWO_POW_10 + (T2_hi % TWO_POW_32 - T2_hi % TWO_POW_22) / TWO_POW_22
            L17_hi = T2_hi * TWO_POW_10 + (T2_lo % TWO_POW_32 - T2_lo % TWO_POW_22) / TWO_POW_22
            L22_lo = T4_lo * TWO_POW_2 + (T4_hi % TWO_POW_32 - T4_hi % TWO_POW_30) / TWO_POW_30
            L22_hi = T4_hi * TWO_POW_2 + (T4_lo % TWO_POW_32 - T4_lo % TWO_POW_30) / TWO_POW_30

            D_lo = bit32_bxor(C2_lo, C4_lo * 2 + (C4_hi % TWO_POW_32 - C4_hi % TWO_POW_31) / TWO_POW_31)
            D_hi = bit32_bxor(C2_hi, C4_hi * 2 + (C4_lo % TWO_POW_32 - C4_lo % TWO_POW_31) / TWO_POW_31)

            T0_lo = bit32_bxor(D_lo, L03_lo)
            T0_hi = bit32_bxor(D_hi, L03_hi)
            T1_lo = bit32_bxor(D_lo, L08_lo)
            T1_hi = bit32_bxor(D_hi, L08_hi)
            T2_lo = bit32_bxor(D_lo, L13_lo)
            T2_hi = bit32_bxor(D_hi, L13_hi)
            T3_lo = bit32_bxor(D_lo, L18_lo)
            T3_hi = bit32_bxor(D_hi, L18_hi)
            T4_lo = bit32_bxor(D_lo, L23_lo)
            T4_hi = bit32_bxor(D_hi, L23_hi)

            L03_lo = (T2_lo % TWO_POW_32 - T2_lo % TWO_POW_21) / TWO_POW_21 + T2_hi * TWO_POW_11
            L03_hi = (T2_hi % TWO_POW_32 - T2_hi % TWO_POW_21) / TWO_POW_21 + T2_lo * TWO_POW_11
            L08_lo = (T4_lo % TWO_POW_32 - T4_lo % TWO_POW_3) / TWO_POW_3 + T4_hi * TWO_POW_29 % TWO_POW_32
            L08_hi = (T4_hi % TWO_POW_32 - T4_hi % TWO_POW_3) / TWO_POW_3 + T4_lo * TWO_POW_29 % TWO_POW_32
            L13_lo = T1_lo * TWO_POW_6 + (T1_hi % TWO_POW_32 - T1_hi % TWO_POW_26) / TWO_POW_26
            L13_hi = T1_hi * TWO_POW_6 + (T1_lo % TWO_POW_32 - T1_lo % TWO_POW_26) / TWO_POW_26
            L18_lo = T3_lo * TWO_POW_15 + (T3_hi % TWO_POW_32 - T3_hi % TWO_POW_17) / TWO_POW_17
            L18_hi = T3_hi * TWO_POW_15 + (T3_lo % TWO_POW_32 - T3_lo % TWO_POW_17) / TWO_POW_17
            L23_lo = (T0_lo % TWO_POW_32 - T0_lo % TWO_POW_2) / TWO_POW_2 + T0_hi * TWO_POW_30 % TWO_POW_32
            L23_hi = (T0_hi % TWO_POW_32 - T0_hi % TWO_POW_2) / TWO_POW_2 + T0_lo * TWO_POW_30 % TWO_POW_32

            D_lo = bit32_bxor(C3_lo, C5_lo * 2 + (C5_hi % TWO_POW_32 - C5_hi % TWO_POW_31) / TWO_POW_31)
            D_hi = bit32_bxor(C3_hi, C5_hi * 2 + (C5_lo % TWO_POW_32 - C5_lo % TWO_POW_31) / TWO_POW_31)

            T0_lo = bit32_bxor(D_lo, L04_lo)
            T0_hi = bit32_bxor(D_hi, L04_hi)
            T1_lo = bit32_bxor(D_lo, L09_lo)
            T1_hi = bit32_bxor(D_hi, L09_hi)
            T2_lo = bit32_bxor(D_lo, L14_lo)
            T2_hi = bit32_bxor(D_hi, L14_hi)
            T3_lo = bit32_bxor(D_lo, L19_lo)
            T3_hi = bit32_bxor(D_hi, L19_hi)
            T4_lo = bit32_bxor(D_lo, L24_lo)
            T4_hi = bit32_bxor(D_hi, L24_hi)

            L04_lo = T3_lo * TWO_POW_21 % TWO_POW_32 + (T3_hi % TWO_POW_32 - T3_hi % TWO_POW_11) / TWO_POW_11
            L04_hi = T3_hi * TWO_POW_21 % TWO_POW_32 + (T3_lo % TWO_POW_32 - T3_lo % TWO_POW_11) / TWO_POW_11
            L09_lo = T0_lo * TWO_POW_28 % TWO_POW_32 + (T0_hi % TWO_POW_32 - T0_hi % TWO_POW_4) / TWO_POW_4
            L09_hi = T0_hi * TWO_POW_28 % TWO_POW_32 + (T0_lo % TWO_POW_32 - T0_lo % TWO_POW_4) / TWO_POW_4
            L14_lo = T2_lo * TWO_POW_25 % TWO_POW_32 + (T2_hi % TWO_POW_32 - T2_hi % TWO_POW_7) / TWO_POW_7
            L14_hi = T2_hi * TWO_POW_25 % TWO_POW_32 + (T2_lo % TWO_POW_32 - T2_lo % TWO_POW_7) / TWO_POW_7
            L19_lo = (T4_lo % TWO_POW_32 - T4_lo % TWO_POW_8) / TWO_POW_8 + T4_hi * TWO_POW_24 % TWO_POW_32
            L19_hi = (T4_hi % TWO_POW_32 - T4_hi % TWO_POW_8) / TWO_POW_8 + T4_lo * TWO_POW_24 % TWO_POW_32
            L24_lo = (T1_lo % TWO_POW_32 - T1_lo % TWO_POW_9) / TWO_POW_9 + T1_hi * TWO_POW_23 % TWO_POW_32
            L24_hi = (T1_hi % TWO_POW_32 - T1_hi % TWO_POW_9) / TWO_POW_9 + T1_lo * TWO_POW_23 % TWO_POW_32

            D_lo = bit32_bxor(C4_lo, C1_lo * 2 + (C1_hi % TWO_POW_32 - C1_hi % TWO_POW_31) / TWO_POW_31)
            D_hi = bit32_bxor(C4_hi, C1_hi * 2 + (C1_lo % TWO_POW_32 - C1_lo % TWO_POW_31) / TWO_POW_31)

            T0_lo = bit32_bxor(D_lo, L05_lo)
            T0_hi = bit32_bxor(D_hi, L05_hi)
            T1_lo = bit32_bxor(D_lo, L10_lo)
            T1_hi = bit32_bxor(D_hi, L10_hi)
            T2_lo = bit32_bxor(D_lo, L15_lo)
            T2_hi = bit32_bxor(D_hi, L15_hi)
            T3_lo = bit32_bxor(D_lo, L20_lo)
            T3_hi = bit32_bxor(D_hi, L20_hi)
            T4_lo = bit32_bxor(D_lo, L25_lo)
            T4_hi = bit32_bxor(D_hi, L25_hi)

            L05_lo = T4_lo * TWO_POW_14 + (T4_hi % TWO_POW_32 - T4_hi % TWO_POW_18) / TWO_POW_18
            L05_hi = T4_hi * TWO_POW_14 + (T4_lo % TWO_POW_32 - T4_lo % TWO_POW_18) / TWO_POW_18
            L10_lo = T1_lo * TWO_POW_20 % TWO_POW_32 + (T1_hi % TWO_POW_32 - T1_hi % TWO_POW_12) / TWO_POW_12
            L10_hi = T1_hi * TWO_POW_20 % TWO_POW_32 + (T1_lo % TWO_POW_32 - T1_lo % TWO_POW_12) / TWO_POW_12
            L15_lo = T3_lo * TWO_POW_8 + (T3_hi % TWO_POW_32 - T3_hi % TWO_POW_24) / TWO_POW_24
            L15_hi = T3_hi * TWO_POW_8 + (T3_lo % TWO_POW_32 - T3_lo % TWO_POW_24) / TWO_POW_24
            L20_lo = T0_lo * TWO_POW_27 % TWO_POW_32 + (T0_hi % TWO_POW_32 - T0_hi % TWO_POW_5) / TWO_POW_5
            L20_hi = T0_hi * TWO_POW_27 % TWO_POW_32 + (T0_lo % TWO_POW_32 - T0_lo % TWO_POW_5) / TWO_POW_5
            L25_lo = (T2_lo % TWO_POW_32 - T2_lo % TWO_POW_25) / TWO_POW_25 + T2_hi * TWO_POW_7
            L25_hi = (T2_hi % TWO_POW_32 - T2_hi % TWO_POW_25) / TWO_POW_25 + T2_lo * TWO_POW_7

            D_lo = bit32_bxor(C5_lo, C2_lo * 2 + (C2_hi % TWO_POW_32 - C2_hi % TWO_POW_31) / TWO_POW_31)
            D_hi = bit32_bxor(C5_hi, C2_hi * 2 + (C2_lo % TWO_POW_32 - C2_lo % TWO_POW_31) / TWO_POW_31)

            T1_lo = bit32_bxor(D_lo, L06_lo)
            T1_hi = bit32_bxor(D_hi, L06_hi)
            T2_lo = bit32_bxor(D_lo, L11_lo)
            T2_hi = bit32_bxor(D_hi, L11_hi)
            T3_lo = bit32_bxor(D_lo, L16_lo)
            T3_hi = bit32_bxor(D_hi, L16_hi)
            T4_lo = bit32_bxor(D_lo, L21_lo)
            T4_hi = bit32_bxor(D_hi, L21_hi)

            L06_lo = T2_lo * TWO_POW_3 + (T2_hi % TWO_POW_32 - T2_hi % TWO_POW_29) / TWO_POW_29
            L06_hi = T2_hi * TWO_POW_3 + (T2_lo % TWO_POW_32 - T2_lo % TWO_POW_29) / TWO_POW_29
            L11_lo = T4_lo * TWO_POW_18 + (T4_hi % TWO_POW_32 - T4_hi % TWO_POW_14) / TWO_POW_14
            L11_hi = T4_hi * TWO_POW_18 + (T4_lo % TWO_POW_32 - T4_lo % TWO_POW_14) / TWO_POW_14
            L16_lo = (T1_lo % TWO_POW_32 - T1_lo % TWO_POW_28) / TWO_POW_28 + T1_hi * TWO_POW_4
            L16_hi = (T1_hi % TWO_POW_32 - T1_hi % TWO_POW_28) / TWO_POW_28 + T1_lo * TWO_POW_4
            L21_lo = (T3_lo % TWO_POW_32 - T3_lo % TWO_POW_23) / TWO_POW_23 + T3_hi * TWO_POW_9
            L21_hi = (T3_hi % TWO_POW_32 - T3_hi % TWO_POW_23) / TWO_POW_23 + T3_lo * TWO_POW_9

            L01_lo = bit32_bxor(D_lo, L01_lo)
            L01_hi = bit32_bxor(D_hi, L01_hi)
            L01_lo, L02_lo, L03_lo, L04_lo, L05_lo =
                bit32_bxor(L01_lo, bit32_band(-1 - L02_lo, L03_lo)),
                bit32_bxor(L02_lo, bit32_band(-1 - L03_lo, L04_lo)),
                bit32_bxor(L03_lo, bit32_band(-1 - L04_lo, L05_lo)),
                bit32_bxor(L04_lo, bit32_band(-1 - L05_lo, L01_lo)),
                bit32_bxor(L05_lo, bit32_band(-1 - L01_lo, L02_lo))
            L01_hi, L02_hi, L03_hi, L04_hi, L05_hi =
                bit32_bxor(L01_hi, bit32_band(-1 - L02_hi, L03_hi)),
                bit32_bxor(L02_hi, bit32_band(-1 - L03_hi, L04_hi)),
                bit32_bxor(L03_hi, bit32_band(-1 - L04_hi, L05_hi)),
                bit32_bxor(L04_hi, bit32_band(-1 - L05_hi, L01_hi)),
                bit32_bxor(L05_hi, bit32_band(-1 - L01_hi, L02_hi))
            L06_lo, L07_lo, L08_lo, L09_lo, L10_lo =
                bit32_bxor(L09_lo, bit32_band(-1 - L10_lo, L06_lo)),
                bit32_bxor(L10_lo, bit32_band(-1 - L06_lo, L07_lo)),
                bit32_bxor(L06_lo, bit32_band(-1 - L07_lo, L08_lo)),
                bit32_bxor(L07_lo, bit32_band(-1 - L08_lo, L09_lo)),
                bit32_bxor(L08_lo, bit32_band(-1 - L09_lo, L10_lo))
            L06_hi, L07_hi, L08_hi, L09_hi, L10_hi =
                bit32_bxor(L09_hi, bit32_band(-1 - L10_hi, L06_hi)),
                bit32_bxor(L10_hi, bit32_band(-1 - L06_hi, L07_hi)),
                bit32_bxor(L06_hi, bit32_band(-1 - L07_hi, L08_hi)),
                bit32_bxor(L07_hi, bit32_band(-1 - L08_hi, L09_hi)),
                bit32_bxor(L08_hi, bit32_band(-1 - L09_hi, L10_hi))
            L11_lo, L12_lo, L13_lo, L14_lo, L15_lo =
                bit32_bxor(L12_lo, bit32_band(-1 - L13_lo, L14_lo)),
                bit32_bxor(L13_lo, bit32_band(-1 - L14_lo, L15_lo)),
                bit32_bxor(L14_lo, bit32_band(-1 - L15_lo, L11_lo)),
                bit32_bxor(L15_lo, bit32_band(-1 - L11_lo, L12_lo)),
                bit32_bxor(L11_lo, bit32_band(-1 - L12_lo, L13_lo))
            L11_hi, L12_hi, L13_hi, L14_hi, L15_hi =
                bit32_bxor(L12_hi, bit32_band(-1 - L13_hi, L14_hi)),
                bit32_bxor(L13_hi, bit32_band(-1 - L14_hi, L15_hi)),
                bit32_bxor(L14_hi, bit32_band(-1 - L15_hi, L11_hi)),
                bit32_bxor(L15_hi, bit32_band(-1 - L11_hi, L12_hi)),
                bit32_bxor(L11_hi, bit32_band(-1 - L12_hi, L13_hi))
            L16_lo, L17_lo, L18_lo, L19_lo, L20_lo =
                bit32_bxor(L20_lo, bit32_band(-1 - L16_lo, L17_lo)),
                bit32_bxor(L16_lo, bit32_band(-1 - L17_lo, L18_lo)),
                bit32_bxor(L17_lo, bit32_band(-1 - L18_lo, L19_lo)),
                bit32_bxor(L18_lo, bit32_band(-1 - L19_lo, L20_lo)),
                bit32_bxor(L19_lo, bit32_band(-1 - L20_lo, L16_lo))
            L16_hi, L17_hi, L18_hi, L19_hi, L20_hi =
                bit32_bxor(L20_hi, bit32_band(-1 - L16_hi, L17_hi)),
                bit32_bxor(L16_hi, bit32_band(-1 - L17_hi, L18_hi)),
                bit32_bxor(L17_hi, bit32_band(-1 - L18_hi, L19_hi)),
                bit32_bxor(L18_hi, bit32_band(-1 - L19_hi, L20_hi)),
                bit32_bxor(L19_hi, bit32_band(-1 - L20_hi, L16_hi))
            L21_lo, L22_lo, L23_lo, L24_lo, L25_lo =
                bit32_bxor(L23_lo, bit32_band(-1 - L24_lo, L25_lo)),
                bit32_bxor(L24_lo, bit32_band(-1 - L25_lo, L21_lo)),
                bit32_bxor(L25_lo, bit32_band(-1 - L21_lo, L22_lo)),
                bit32_bxor(L21_lo, bit32_band(-1 - L22_lo, L23_lo)),
                bit32_bxor(L22_lo, bit32_band(-1 - L23_lo, L24_lo))
            L21_hi, L22_hi, L23_hi, L24_hi, L25_hi =
                bit32_bxor(L23_hi, bit32_band(-1 - L24_hi, L25_hi)),
                bit32_bxor(L24_hi, bit32_band(-1 - L25_hi, L21_hi)),
                bit32_bxor(L25_hi, bit32_band(-1 - L21_hi, L22_hi)),
                bit32_bxor(L21_hi, bit32_band(-1 - L22_hi, L23_hi)),
                bit32_bxor(L22_hi, bit32_band(-1 - L23_hi, L24_hi))
            L01_lo = bit32_bxor(L01_lo, RC_lo[round_idx])
            L01_hi += RC_hi[round_idx]
        end

        lanes_lo[1], lanes_hi[1] = L01_lo, L01_hi
        lanes_lo[2], lanes_hi[2] = L02_lo, L02_hi
        lanes_lo[3], lanes_hi[3] = L03_lo, L03_hi
        lanes_lo[4], lanes_hi[4] = L04_lo, L04_hi
        lanes_lo[5], lanes_hi[5] = L05_lo, L05_hi
        lanes_lo[6], lanes_hi[6] = L06_lo, L06_hi
        lanes_lo[7], lanes_hi[7] = L07_lo, L07_hi
        lanes_lo[8], lanes_hi[8] = L08_lo, L08_hi
        lanes_lo[9], lanes_hi[9] = L09_lo, L09_hi
        lanes_lo[10], lanes_hi[10] = L10_lo, L10_hi
        lanes_lo[11], lanes_hi[11] = L11_lo, L11_hi
        lanes_lo[12], lanes_hi[12] = L12_lo, L12_hi
        lanes_lo[13], lanes_hi[13] = L13_lo, L13_hi
        lanes_lo[14], lanes_hi[14] = L14_lo, L14_hi
        lanes_lo[15], lanes_hi[15] = L15_lo, L15_hi
        lanes_lo[16], lanes_hi[16] = L16_lo, L16_hi
        lanes_lo[17], lanes_hi[17] = L17_lo, L17_hi
        lanes_lo[18], lanes_hi[18] = L18_lo, L18_hi
        lanes_lo[19], lanes_hi[19] = L19_lo, L19_hi
        lanes_lo[20], lanes_hi[20] = L20_lo, L20_hi
        lanes_lo[21], lanes_hi[21] = L21_lo, L21_hi
        lanes_lo[22], lanes_hi[22] = L22_lo, L22_hi
        lanes_lo[23], lanes_hi[23] = L23_lo, L23_hi
        lanes_lo[24], lanes_hi[24] = L24_lo, L24_hi
        lanes_lo[25], lanes_hi[25] = L25_lo, L25_hi
    end
end

--------------------------------------------------------------------------------
-- MAGIC NUMBERS CALCULATOR
--------------------------------------------------------------------------------

do
    local function mul(src1, src2, factor, result_length)
        local result, carry, value, weight = table.create(result_length), 0, 0, 1
        for j = 1, result_length do
            for k = math.max(1, j + 1 - #src2), math.min(j, #src1) do
                carry += factor * src1[k] * src2[j + 1 - k]
            end

            local digit = carry % TWO_POW_24
            result[j] = math.floor(digit)
            carry = (carry - digit) / TWO_POW_24
            value += digit * weight
            weight *= TWO_POW_24
        end

        return result, value
    end

    local idx, step, p, one, sqrt_hi, sqrt_lo = 0, { 4, 1, 2, -2, 2 }, 4, { 1 }, sha2_H_hi, sha2_H_lo
    repeat
        p += step[p % 6]
        local d = 1
        repeat
            d += step[d % 6]
            if d * d > p then
                local root = p ^ (1 / 3)
                local R = root * TWO_POW_40
                R = mul(table.create(1, math.floor(R)), one, 1, 2)
                local _, delta = mul(R, mul(R, R, 1, 4), -1, 4)
                local hi = R[2] % 65536 * 65536 + math.floor(R[1] / 256)
                local lo = R[1] % 256 * 16777216 + math.floor(delta * (TWO_POW_NEG_56 / 3) * root / p)

                if idx < 16 then
                    root = math.sqrt(p)
                    R = root * TWO_POW_40
                    R = mul(table.create(1, math.floor(R)), one, 1, 2)
                    _, delta = mul(R, R, -1, 2)
                    local hi = R[2] % 65536 * 65536 + math.floor(R[1] / 256)
                    local lo = R[1] % 256 * 16777216 + math.floor(delta * TWO_POW_NEG_17 / root)
                    local idx = idx % 8 + 1
                    sha2_H_ext256[224][idx] = lo
                    sqrt_hi[idx], sqrt_lo[idx] = hi, lo + hi * hi_factor
                    if idx > 7 then
                        sqrt_hi, sqrt_lo = sha2_H_ext512_hi[384], sha2_H_ext512_lo[384]
                    end
                end

                idx += 1
                sha2_K_hi[idx], sha2_K_lo[idx] = hi, lo % K_lo_modulo + hi * hi_factor
                break
            end
        until p % d == 0
    until idx > 79
end

-- Calculating IVs for SHA512/224 and SHA512/256
for width = 224, 256, 32 do
    local H_lo, H_hi = {}, nil
    if XOR64A5 then
        for j = 1, 8 do
            H_lo[j] = XOR64A5(sha2_H_lo[j])
        end
    else
        H_hi = {}
        for j = 1, 8 do
            H_lo[j] = bit32_bxor(sha2_H_lo[j], 0xA5A5A5A5) % 4294967296
            H_hi[j] = bit32_bxor(sha2_H_hi[j], 0xA5A5A5A5) % 4294967296
        end
    end

    sha512_feed_128(H_lo, H_hi, `SHA-512/{width}\128{string.rep("\0", 115)}\88`, 0, 128)
    sha2_H_ext512_lo[width] = H_lo
    sha2_H_ext512_hi[width] = H_hi
end

-- Constants for MD5
do
    for idx = 1, 64 do
        local hi, lo = math.modf(math.abs(math.sin(idx)) * TWO_POW_16)
        md5_K[idx] = hi * 65536 + math.floor(lo * TWO_POW_16)
    end
end

-- Constants for SHA3
do
    local sh_reg = 29
    local function next_bit()
        local r = sh_reg % 2
        sh_reg = bit32_bxor((sh_reg - r) / 2, 142 * r)
        return r
    end

    for idx = 1, 24 do
        local lo, m = 0, nil
        for _ = 1, 6 do
            m = if m then m * m * 2 else 1
            lo += next_bit() * m
        end

        local hi = next_bit() * m
        sha3_RC_hi[idx], sha3_RC_lo[idx] = hi, lo + hi * hi_factor_keccak
    end
end

--------------------------------------------------------------------------------
-- MAIN FUNCTIONS
--------------------------------------------------------------------------------

local function sha256ext(width: number, message: string?): string | (string?) -> string?
    local Array256 = sha2_H_ext256[width]
    local length, tail = 0, ""
    local H = table.create(8)
    H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] =
        Array256[1], Array256[2], Array256[3], Array256[4], Array256[5], Array256[6], Array256[7], Array256[8]

    local function partial(message_part: string?): any
        if message_part then
            local partLength = #message_part
            if tail then
                length += partLength
                local offs = 0
                local tailLength = #tail
                if tail ~= "" and tailLength + partLength >= 64 then
                    offs = 64 - tailLength
                    sha256_feed_64(H, tail .. string.sub(message_part, 1, offs), 0, 64)
                    tail = ""
                end

                local size = partLength - offs
                local size_tail = size % 64
                sha256_feed_64(H, message_part, offs, size - size_tail)
                tail = tail .. string.sub(message_part, partLength + 1 - size_tail)
                return partial
            else
                error("Adding more chunks is not allowed after receiving the result", 2)
            end
        else
            if tail then
                local final_blocks = table.create(10)
                final_blocks[1] = tail
                final_blocks[2] = "\128"
                final_blocks[3] = string.rep("\0", (-9 - length) % 64 + 1)

                tail = nil
                length *= 8 / TWO56_POW_7
                for j = 4, 10 do
                    length = length % 1 * 256
                    final_blocks[j] = string.char(math.floor(length))
                end

                final_blocks = table.concat(final_blocks)
                sha256_feed_64(H, final_blocks, 0, #final_blocks)
                local max_reg = width / 32
                for j = 1, max_reg do
                    H[j] = string.format("%08x", H[j] % 4294967296)
                end

                H = table.concat(H, "", 1, max_reg)
            end

            return H
        end
    end

    if message then
        return partial(message)()
    else
        return partial
    end
end

local function sha512ext(width: number, message: string?): string | (string?) -> string?
    local length, tail, H_lo, H_hi =
        0,
        "",
        table.pack(table.unpack(sha2_H_ext512_lo[width])),
        not HEX64 and table.pack(table.unpack(sha2_H_ext512_hi[width]))

    local function partial(message_part: string?): any
        if message_part then
            local partLength = #message_part
            if tail then
                length += partLength
                local offs = 0
                if tail ~= "" and #tail + partLength >= 128 then
                    offs = 128 - #tail
                    sha512_feed_128(H_lo, H_hi, tail .. string.sub(message_part, 1, offs), 0, 128)
                    tail = ""
                end

                local size = partLength - offs
                local size_tail = size % 128
                sha512_feed_128(H_lo, H_hi, message_part, offs, size - size_tail)
                tail = tail .. string.sub(message_part, partLength + 1 - size_tail)
                return partial
            else
                error("Adding more chunks is not allowed after receiving the result", 2)
            end
        else
            if tail then
                local final_blocks = table.create(3)
                final_blocks[1] = tail
                final_blocks[2] = "\128"
                final_blocks[3] = string.rep("\0", (-17 - length) % 128 + 9)

                tail = nil
                length *= 8 / TWO56_POW_7
                for j = 4, 10 do
                    length = length % 1 * 256
                    final_blocks[j] = string.char(math.floor(length))
                end

                final_blocks = table.concat(final_blocks)
                sha512_feed_128(H_lo, H_hi, final_blocks, 0, #final_blocks)
                local max_reg = math.ceil(width / 64)

                if HEX64 then
                    for j = 1, max_reg do
                        H_lo[j] = HEX64(H_lo[j])
                    end
                else
                    for j = 1, max_reg do
                        H_lo[j] = string.format("%08x", H_hi[j] % 4294967296)
                            .. string.format("%08x", H_lo[j] % 4294967296)
                    end

                    H_hi = nil
                end

                H_lo = string.sub(table.concat(H_lo, "", 1, max_reg), 1, width / 4)
            end

            return H_lo
        end
    end

    if message then
        return partial(message)()
    else
        return partial
    end
end

local function md5(message: string?): string | (string?) -> string?
    local H, length, tail = table.create(4), 0, ""
    H[1], H[2], H[3], H[4] = md5_sha1_H[1], md5_sha1_H[2], md5_sha1_H[3], md5_sha1_H[4]

    local function partial(message_part: string?): any
        if message_part then
            local partLength = #message_part
            if tail then
                length += partLength
                local offs = 0
                if tail ~= "" and #tail + partLength >= 64 then
                    offs = 64 - #tail
                    md5_feed_64(H, tail .. string.sub(message_part, 1, offs), 0, 64)
                    tail = ""
                end

                local size = partLength - offs
                local size_tail = size % 64
                md5_feed_64(H, message_part, offs, size - size_tail)
                tail = tail .. string.sub(message_part, partLength + 1 - size_tail)
                return partial
            else
                error("Adding more chunks is not allowed after receiving the result", 2)
            end
        else
            if tail then
                local final_blocks = table.create(3)
                final_blocks[1] = tail
                final_blocks[2] = "\128"
                final_blocks[3] = string.rep("\0", (-9 - length) % 64)
                tail = nil
                length *= 8
                for j = 4, 11 do
                    local low_byte = length % 256
                    final_blocks[j] = string.char(low_byte)
                    length = (length - low_byte) / 256
                end

                final_blocks = table.concat(final_blocks)
                md5_feed_64(H, final_blocks, 0, #final_blocks)
                for j = 1, 4 do
                    H[j] = string.format("%08x", H[j] % 4294967296)
                end

                H = string.gsub(table.concat(H), "(..)(..)(..)(..)", "%4%3%2%1")
            end

            return H
        end
    end

    if message then
        return partial(message)()
    else
        return partial
    end
end

local function sha1(message: string?): string | (string?) -> string?
    local H, length, tail = table.pack(table.unpack(md5_sha1_H)), 0, ""

    local function partial(message_part: string?): any
        if message_part then
            local partLength = #message_part
            if tail then
                length += partLength
                local offs = 0
                if tail ~= "" and #tail + partLength >= 64 then
                    offs = 64 - #tail
                    sha1_feed_64(H, tail .. string.sub(message_part, 1, offs), 0, 64)
                    tail = ""
                end

                local size = partLength - offs
                local size_tail = size % 64
                sha1_feed_64(H, message_part, offs, size - size_tail)
                tail = tail .. string.sub(message_part, partLength + 1 - size_tail)
                return partial
            else
                error("Adding more chunks is not allowed after receiving the result", 2)
            end
        else
            if tail then
                local final_blocks = table.create(10)
                final_blocks[1] = tail
                final_blocks[2] = "\128"
                final_blocks[3] = string.rep("\0", (-9 - length) % 64 + 1)
                tail = nil

                length *= 8 / TWO56_POW_7
                for j = 4, 10 do
                    length = length % 1 * 256
                    final_blocks[j] = string.char(math.floor(length))
                end

                final_blocks = table.concat(final_blocks)
                sha1_feed_64(H, final_blocks, 0, #final_blocks)
                for j = 1, 5 do
                    H[j] = string.format("%08x", H[j] % 4294967296)
                end

                H = table.concat(H)
            end

            return H
        end
    end

    if message then
        return partial(message)()
    else
        return partial
    end
end

local function keccak(
    block_size_in_bytes: number,
    digest_size_in_bytes: number,
    is_SHAKE: boolean,
    message: string?
): string | (string?) -> string?
    if type(digest_size_in_bytes) ~= "number" then
        error("Argument 'digest_size_in_bytes' must be a number", 2)
    end

    local tail, lanes_lo, lanes_hi = "", table.create(25, 0), hi_factor_keccak == 0 and table.create(25, 0)
    local result

    local function partial(message_part: string?): any
        if message_part then
            local partLength = #message_part
            if tail then
                local offs = 0
                if tail ~= "" and #tail + partLength >= block_size_in_bytes then
                    offs = block_size_in_bytes - #tail
                    keccak_feed(
                        lanes_lo,
                        lanes_hi,
                        tail .. string.sub(message_part, 1, offs),
                        0,
                        block_size_in_bytes,
                        block_size_in_bytes
                    )
                    tail = ""
                end

                local size = partLength - offs
                local size_tail = size % block_size_in_bytes
                keccak_feed(lanes_lo, lanes_hi, message_part, offs, size - size_tail, block_size_in_bytes)
                tail = tail .. string.sub(message_part, partLength + 1 - size_tail)
                return partial
            else
                error("Adding more chunks is not allowed after receiving the result", 2)
            end
        else
            if tail then
                local gap_start = if is_SHAKE then 31 else 6
                tail = tail
                    .. (
                        if #tail + 1 == block_size_in_bytes
                            then string.char(gap_start + 128)
                            else string.char(gap_start)
                                .. string.rep("\0", (-2 - #tail) % block_size_in_bytes)
                                .. "\128"
                    )
                keccak_feed(lanes_lo, lanes_hi, tail, 0, #tail, block_size_in_bytes)
                tail = nil

                local lanes_used = 0
                local total_lanes = math.floor(block_size_in_bytes / 8)
                local qwords = {}

                local function get_next_qwords_of_digest(qwords_qty)
                    if lanes_used >= total_lanes then
                        keccak_feed(lanes_lo, lanes_hi, "\0\0\0\0\0\0\0\0", 0, 8, 8)
                        lanes_used = 0
                    end

                    qwords_qty = math.floor(math.min(qwords_qty, total_lanes - lanes_used))
                    if hi_factor_keccak ~= 0 then
                        for j = 1, qwords_qty do
                            qwords[j] = HEX64(lanes_lo[lanes_used + j - 1 + lanes_index_base])
                        end
                    else
                        for j = 1, qwords_qty do
                            qwords[j] = string.format("%08x", lanes_hi[lanes_used + j] % 4294967296)
                                .. string.format("%08x", lanes_lo[lanes_used + j] % 4294967296)
                        end
                    end

                    lanes_used += qwords_qty
                    return string.gsub(
                        table.concat(qwords, "", 1, qwords_qty),
                        "(..)(..)(..)(..)(..)(..)(..)(..)",
                        "%8%7%6%5%4%3%2%1"
                    ),
                        qwords_qty * 8
                end

                local parts = {}
                local last_part, last_part_size = "", 0

                local function get_next_part_of_digest(bytes_needed)
                    bytes_needed = bytes_needed or 1
                    if bytes_needed <= last_part_size then
                        last_part_size -= bytes_needed
                        local part_size_in_nibbles = bytes_needed * 2
                        local result = string.sub(last_part, 1, part_size_in_nibbles)
                        last_part = string.sub(last_part, part_size_in_nibbles + 1)
                        return result
                    end

                    local parts_qty = 0
                    if last_part_size > 0 then
                        parts_qty = 1
                        parts[parts_qty] = last_part
                        bytes_needed -= last_part_size
                    end

                    while bytes_needed >= 8 do
                        local next_part, next_part_size = get_next_qwords_of_digest(bytes_needed / 8)
                        parts_qty += 1
                        parts[parts_qty] = next_part
                        bytes_needed -= next_part_size
                    end

                    if bytes_needed > 0 then
                        last_part, last_part_size = get_next_qwords_of_digest(1)
                        parts_qty += 1
                        parts[parts_qty] = get_next_part_of_digest(bytes_needed)
                    else
                        last_part, last_part_size = "", 0
                    end

                    return table.concat(parts, "", 1, parts_qty)
                end

                if digest_size_in_bytes < 0 then
                    result = get_next_part_of_digest
                else
                    result = get_next_part_of_digest(digest_size_in_bytes)
                end
            end

            return result
        end
    end

    if message then
        return partial(message)()
    else
        return partial
    end
end

--------------------------------------------------------------------------------
-- UTILITY FUNCTIONS
--------------------------------------------------------------------------------

local function hexToBinFunction(hh: string): string
    return string.char(tonumber(hh, 16) :: number)
end

local function hex2bin(hex_string: string): string
    assert(type(hex_string) == "string", "argument #1 must be a string")
    return (string.gsub(hex_string, "%x%x", hexToBinFunction))
end

local base64_symbols: { [string | number]: string | number } = {
    ["+"] = 62,
    ["-"] = 62,
    [62] = "+",
    ["/"] = 63,
    ["_"] = 63,
    [63] = "/",
    ["="] = -1,
    ["."] = -1,
    [-1] = "=",
}

local symbol_index = 0
for _, pair in ipairs({ "AZ", "az", "09" }) do
    for ascii = string.byte(pair), string.byte(pair, 2) do
        local ch = string.char(ascii)
        base64_symbols[ch] = symbol_index
        base64_symbols[symbol_index] = ch
        symbol_index += 1
    end
end

local function bin2base64(binary_string: string): string
    assert(type(binary_string) == "string", "argument #1 must be a string")
    local result = table.create(math.ceil(#binary_string / 3))
    local length = 0

    for pos = 1, #binary_string, 3 do
        local c1, c2, c3, c4 = string.byte(string.sub(binary_string, pos, pos + 2) .. "\0", 1, -1)
        length += 1
        result[length] = base64_symbols[math.floor(c1 / 4)]
            .. base64_symbols[c1 % 4 * 16 + math.floor(c2 / 16)]
            .. base64_symbols[if c3 then c2 % 16 * 4 + math.floor(c3 / 64) else -1]
            .. base64_symbols[if c4 then c3 % 64 else -1]
    end

    return table.concat(result)
end

local function base642bin(base64_string: string): string
    assert(type(base64_string) == "string", "argument #1 must be a string")
    local result, chars_qty = {}, 3
    for pos, ch in string.gmatch(string.gsub(base64_string, "%s+", ""), "()(.)") do
        local code = base64_symbols[ch] :: number
        if code < 0 then
            chars_qty -= 1
            code = 0
        end

        local idx = pos % 4
        if idx > 0 then
            result[-idx] = code
        else
            local c1 = result[-1] * 4 + math.floor(result[-2] / 16)
            local c2 = (result[-2] % 16) * 16 + math.floor(result[-3] / 4)
            local c3 = (result[-3] % 4) * 64 + code
            result[#result + 1] = string.sub(string.char(c1, c2, c3), 1, chars_qty)
        end
    end

    return table.concat(result)
end

--------------------------------------------------------------------------------
-- HMAC
--------------------------------------------------------------------------------

local block_size_for_HMAC: { [any]: number }

local BinaryStringMap: { [string]: string } = {}
for index = 0, 255 do
    BinaryStringMap[string.format("%02x", index)] = string.char(index)
end

local function hmac(hash_func: any, key: string, message: string?, asBinary: boolean?): any
    local block_size = block_size_for_HMAC[hash_func]
    if not block_size then
        error("Unknown hash function", 2)
    end

    local keyLength = #key
    if keyLength > block_size then
        key = string.gsub(hash_func(key), "%x%x", hexToBinFunction)
        keyLength = #key
    end

    local append = hash_func()(string.gsub(key, ".", function(c)
        return string.char(bit32_bxor(string.byte(c), 0x36))
    end) .. string.rep("6", block_size - keyLength))

    local result

    local function partial(message_part: string?): any
        if not message_part then
            result = result
                or hash_func(
                    string.gsub(key, ".", function(c)
                        return string.char(bit32_bxor(string.byte(c), 0x5c))
                    end)
                        .. string.rep("\\", block_size - keyLength)
                        .. (string.gsub(append(), "%x%x", hexToBinFunction))
                )

            return result
        elseif result then
            error("Adding more chunks is not allowed after receiving the result", 2)
        else
            append(message_part)
            return partial
        end
    end

    if message then
        local finalMessage = partial(message)()
        return if asBinary then (string.gsub(finalMessage, "%x%x", BinaryStringMap)) else finalMessage
    else
        return partial
    end
end

--------------------------------------------------------------------------------
-- MODULE
--------------------------------------------------------------------------------

local HashLib = {
    md5 = md5,
    sha1 = sha1,
    sha224 = function(message: string?): any
        return sha256ext(224, message)
    end,
    sha256 = function(message: string?): any
        return sha256ext(256, message)
    end,
    sha512x224 = function(message: string?): any
        return sha512ext(224, message)
    end,
    sha512x256 = function(message: string?): any
        return sha512ext(256, message)
    end,
    sha384 = function(message: string?): any
        return sha512ext(384, message)
    end,
    sha512 = function(message: string?): any
        return sha512ext(512, message)
    end,
    sha3x224 = function(message: string?): any
        return keccak((1600 - 2 * 224) / 8, 224 / 8, false, message)
    end,
    sha3x256 = function(message: string?): any
        return keccak((1600 - 2 * 256) / 8, 256 / 8, false, message)
    end,
    sha3x384 = function(message: string?): any
        return keccak((1600 - 2 * 384) / 8, 384 / 8, false, message)
    end,
    sha3x512 = function(message: string?): any
        return keccak((1600 - 2 * 512) / 8, 512 / 8, false, message)
    end,
    shake128 = function(message: string, digest_size_in_bytes: number): any
        return keccak((1600 - 2 * 128) / 8, digest_size_in_bytes, true, message)
    end,
    shake256 = function(message: string, digest_size_in_bytes: number): any
        return keccak((1600 - 2 * 256) / 8, digest_size_in_bytes, true, message)
    end,
    hmac = hmac,
    hexToBin = hex2bin,
    base64ToBin = base642bin,
    binToBase64 = bin2base64,
    base64Encode = Base64.encode,
    base64Decode = Base64.decode,
}

block_size_for_HMAC = {
    [HashLib.md5] = 64,
    [HashLib.sha1] = 64,
    [HashLib.sha224] = 64,
    [HashLib.sha256] = 64,
    [HashLib.sha512x224] = 128,
    [HashLib.sha512x256] = 128,
    [HashLib.sha384] = 128,
    [HashLib.sha512] = 128,
    [HashLib.sha3x224] = (1600 - 2 * 224) / 8,
    [HashLib.sha3x256] = (1600 - 2 * 256) / 8,
    [HashLib.sha3x384] = (1600 - 2 * 384) / 8,
    [HashLib.sha3x512] = (1600 - 2 * 512) / 8,
}

return HashLib :: HashLib
]==], "@TAP/hashlib")()

local base64 = safeLoadstring([==[
local lookupValueToCharacter = buffer.create(64)
local lookupCharacterToValue = buffer.create(256)

local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local padding = string.byte("=")

for index = 1, 64 do
	local value = index - 1
	local character = string.byte(alphabet, index)

	buffer.writeu8(lookupValueToCharacter, value, character)
	buffer.writeu8(lookupCharacterToValue, character, value)
end

local function encode(input: buffer): buffer
	local inputLength = buffer.len(input)
	local inputChunks = math.ceil(inputLength / 3)

	local outputLength = inputChunks * 4
	local output = buffer.create(outputLength)

	for chunkIndex = 1, inputChunks - 1 do
		local inputIndex = (chunkIndex - 1) * 3
		local outputIndex = (chunkIndex - 1) * 4

		local chunk = bit32.byteswap(buffer.readu32(input, inputIndex))

		local value1 = bit32.rshift(chunk, 26)
		local value2 = bit32.band(bit32.rshift(chunk, 20), 0b111111)
		local value3 = bit32.band(bit32.rshift(chunk, 14), 0b111111)
		local value4 = bit32.band(bit32.rshift(chunk, 8), 0b111111)

		buffer.writeu8(output, outputIndex, buffer.readu8(lookupValueToCharacter, value1))
		buffer.writeu8(output, outputIndex + 1, buffer.readu8(lookupValueToCharacter, value2))
		buffer.writeu8(output, outputIndex + 2, buffer.readu8(lookupValueToCharacter, value3))
		buffer.writeu8(output, outputIndex + 3, buffer.readu8(lookupValueToCharacter, value4))
	end

	local inputRemainder = inputLength % 3

	if inputRemainder == 1 then
		local chunk = buffer.readu8(input, inputLength - 1)

		local value1 = bit32.rshift(chunk, 2)
		local value2 = bit32.band(bit32.lshift(chunk, 4), 0b111111)

		buffer.writeu8(output, outputLength - 4, buffer.readu8(lookupValueToCharacter, value1))
		buffer.writeu8(output, outputLength - 3, buffer.readu8(lookupValueToCharacter, value2))
		buffer.writeu8(output, outputLength - 2, padding)
		buffer.writeu8(output, outputLength - 1, padding)
	elseif inputRemainder == 2 then
		local chunk = bit32.bor(
			bit32.lshift(buffer.readu8(input, inputLength - 2), 8),
			buffer.readu8(input, inputLength - 1)
		)

		local value1 = bit32.rshift(chunk, 10)
		local value2 = bit32.band(bit32.rshift(chunk, 4), 0b111111)
		local value3 = bit32.band(bit32.lshift(chunk, 2), 0b111111)

		buffer.writeu8(output, outputLength - 4, buffer.readu8(lookupValueToCharacter, value1))
		buffer.writeu8(output, outputLength - 3, buffer.readu8(lookupValueToCharacter, value2))
		buffer.writeu8(output, outputLength - 2, buffer.readu8(lookupValueToCharacter, value3))
		buffer.writeu8(output, outputLength - 1, padding)
	elseif inputRemainder == 0 and inputLength ~= 0 then
		local chunk = bit32.bor(
			bit32.lshift(buffer.readu8(input, inputLength - 3), 16),
			bit32.lshift(buffer.readu8(input, inputLength - 2), 8),
			buffer.readu8(input, inputLength - 1)
		)

		local value1 = bit32.rshift(chunk, 18)
		local value2 = bit32.band(bit32.rshift(chunk, 12), 0b111111)
		local value3 = bit32.band(bit32.rshift(chunk, 6), 0b111111)
		local value4 = bit32.band(chunk, 0b111111)

		buffer.writeu8(output, outputLength - 4, buffer.readu8(lookupValueToCharacter, value1))
		buffer.writeu8(output, outputLength - 3, buffer.readu8(lookupValueToCharacter, value2))
		buffer.writeu8(output, outputLength - 2, buffer.readu8(lookupValueToCharacter, value3))
		buffer.writeu8(output, outputLength - 1, buffer.readu8(lookupValueToCharacter, value4))
	end

	return output
end

local function decode(input: buffer): buffer
	local inputLength = buffer.len(input)
	local inputChunks = math.ceil(inputLength / 4)

	local inputPadding = 0
	if inputLength ~= 0 then
		if buffer.readu8(input, inputLength - 1) == padding then inputPadding += 1 end
		if buffer.readu8(input, inputLength - 2) == padding then inputPadding += 1 end
	end

	local outputLength = inputChunks * 3 - inputPadding
	local output = buffer.create(outputLength)

	for chunkIndex = 1, inputChunks - 1 do
		local inputIndex = (chunkIndex - 1) * 4
		local outputIndex = (chunkIndex - 1) * 3

		local value1 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, inputIndex))
		local value2 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, inputIndex + 1))
		local value3 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, inputIndex + 2))
		local value4 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, inputIndex + 3))

		local chunk = bit32.bor(
			bit32.lshift(value1, 18),
			bit32.lshift(value2, 12),
			bit32.lshift(value3, 6),
			value4
		)

		local character1 = bit32.rshift(chunk, 16)
		local character2 = bit32.band(bit32.rshift(chunk, 8), 0b11111111)
		local character3 = bit32.band(chunk, 0b11111111)

		buffer.writeu8(output, outputIndex, character1)
		buffer.writeu8(output, outputIndex + 1, character2)
		buffer.writeu8(output, outputIndex + 2, character3)
	end

	if inputLength ~= 0 then
		local lastInputIndex = (inputChunks - 1) * 4
		local lastOutputIndex = (inputChunks - 1) * 3

		local lastValue1 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, lastInputIndex))
		local lastValue2 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, lastInputIndex + 1))
		local lastValue3 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, lastInputIndex + 2))
		local lastValue4 = buffer.readu8(lookupCharacterToValue, buffer.readu8(input, lastInputIndex + 3))

		local lastChunk = bit32.bor(
			bit32.lshift(lastValue1, 18),
			bit32.lshift(lastValue2, 12),
			bit32.lshift(lastValue3, 6),
			lastValue4
		)

		if inputPadding <= 2 then
			local lastCharacter1 = bit32.rshift(lastChunk, 16)
			buffer.writeu8(output, lastOutputIndex, lastCharacter1)

			if inputPadding <= 1 then
				local lastCharacter2 = bit32.band(bit32.rshift(lastChunk, 8), 0b11111111)
				buffer.writeu8(output, lastOutputIndex + 1, lastCharacter2)

				if inputPadding == 0 then
					local lastCharacter3 = bit32.band(lastChunk, 0b11111111)
					buffer.writeu8(output, lastOutputIndex + 2, lastCharacter3)
				end
			end
		end
	end

	return output
end

return {
	encode = encode,
	decode = decode,
}
]==], "@TAP/base64")()

local rgAES = safeLoadstring([===[
--!native
--!optimize 2
--!strict
--[=[=========================================================================================

ADVANCED ENCRYPTION STANDARD (AES/Rijndael)
by @RobloxGamerPro200007 (verify the original asset)

This is an optimized version of my previous work using this algorithm and porting
it to Roblox from scratch. It overcomplicated the algorithm a lot so it could be
used for educational purposes only.

Now, this current version implements better features like buffer manipulation,
which serves as raw binary data which led to better performance as well as
native Luau support for even more performance!

Finally, this work has been made with the only purpose of getting the maximum
performance possible, as well as implementing custom Object-Oriented Programming
with the addition of AesCipher objects which their functions are stated below.

Hope this helps!

----------------------------------------------------------------------------------------------

REFERENCE

	* Aes library
	This holds the main functions of key management and block cipher modes of operation.

	- FUNCTIONS:

	  new (masterKey: string or buffer, mode: table, pad: table): AesCipher
	Creates an AesCipher object with given key, given mode options:
		> FwdMode (function): Function that holds the encryption mode
		> InvMode (function): Function that holds the decryption mode
		> SegmentSize (number): Segment size for block selection and padding
	and given padding options:
		> Pad (function): Function which pads plaintext.
		> Unpad (function): Function which removes padding from plaintext.
		> Overwrite (boolean): Whether if ciphertext is overwritten while decrypting.
	Other options can be stated for mode and padding. ECB mode is used by default.

	  expandKey (key: string or buffer, output: buffer): buffer
	Key expansion that generates round keys by using the AES key schedule. Key size
	must be either 16 (AES-128), 24 (AES-192) or 32 (AES-256) bytes long.

	  fromKey (roundKeys: string or buffer, options: table): AesCipher
	Creates an AesCipher object with processed round keys and the options stated
	above. Round keys size must be either 176, 208 or 240 bytes long.

	- PROPERTIES:

	  modes: table
	Holds built-in block cipher modes of operation. Includes ECB, CBC, PCBC, CFB, OFB
	and CTR modes of operation.

	  pads: table
	Holds built-in padding algorithms. Includes non-padding, ANSI X9.23, ISO 10126,
	PCKS#7, ISO/IEC 7816-4 and zero padding

	* AesCipher data type
	This custom object is used for actual symmetric encryption and decryption of data.
	Plaintexts and ciphertexts are split into 4 x 4 byte matrices. Properties and
	methods have read-only access.

	- PROPERTIES:

	  Key: string
	Cipher's master key.

	  Length: number
	Key length. Can be 16, 24 or 32 bytes.

	  Mode: table
	Block cipher mode of operation.

	  Padding: table
	Cryptographic padding algorithm.

	  RoundKeys: string
	Cipher's expanded round keys.

	- METHODS:

	  Encrypt (plaintext: string or buffer, output: buffer, ...: Variant): buffer
	Applies symmetric encryption into a plaintext and returns it in an output buffer.

	  EncryptBlock (plaintext: buffer, offset: number, output: buffer,
	  offsetOut: number): void
	Block cipher encryption of a 16-byte word. Custom offsets can be set for buffer
	reusing.

	  Decrypt (ciphertext: string or buffer, output: buffer, ...: Variant): buffer
	Applies symmetric decryption into a plaintext and returns it in an output buffer.

	  DecryptBlock (ciphertext: buffer, offset: number, output: buffer,
	  offsetOut: number): void
	Block cipher decryption of a 16-byte word. Custom offsets can be set for buffer
	reusing.

	  Destroy (): void
	Locks all properties and methods so it cannot be used again. It is intented
	to prevent accidental leaks when communicating remotely.

----------------------------------------------------------------------------------------------

HISTORY (UTC)

- Dic 25, 2023. 03:00:00	|	Finished MainModule and Modes
- Sep 01, 2024. 18:15:00	|	Added Pads; Revised
- Sep 09, 2024, 03:00:00	|	Released

=========================================================================================]=]--
-->> TODO: Suggest features at [devforum.roblox.com/t/2009120]

----------------------------------------------------------------------------------------------
--  GLOBALS' LOCALIZATION for VM performance and secure environment
----------------------------------------------------------------------------------------------

local error = error
local newproxy = newproxy
local getmetatable = getmetatable
local typeof = typeof


local bit32_bxor = bit32.bxor
local bit32_rrotate = bit32.rrotate


local buffer_copy = 		buffer.copy
local buffer_create = 		buffer.create
local buffer_fromstring = 	buffer.fromstring
local buffer_len = 			buffer.len
local buffer_readu8 = 		buffer.readu8
local buffer_readu16 = 		buffer.readu16
local buffer_readu32 = 		buffer.readu32
local buffer_tostring = 	buffer.tostring
local buffer_writestring = 	buffer.writestring
local buffer_writeu8 = 		buffer.writeu8
local buffer_writeu16 = 	buffer.writeu16
local buffer_writeu32 = 	buffer.writeu32


local math_floor = math.floor


local string_sub = string.sub




local S_BOX_16 = 	buffer_create(131072)
local S_MIX0 = 		buffer_create(65536)
local S_MIX1 = 		buffer_create(65536)
local INV_S_XOR = 	buffer_create(65536)
local INV_MIX0 = 	buffer_create(65536)
local INV_MIX1 = 	buffer_create(65536)





local function keySchedule(key: buffer | string, len: number, out: buffer, raw: boolean): buffer
	if raw then
		buffer_copy(out, 0, key :: buffer, 0, len)
	else
		buffer_writestring(out, 0, key :: string, len)
	end
	local word = bit32_rrotate(buffer_readu32(out, len - 4), 8)
	local rc = 0.5

	if len == 32 then
		for offs = 32, 192, 32 do
			rc = rc * 2 % 229
			word = bit32_bxor(buffer_readu32(out, offs - 32), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
				buffer_readu16(S_BOX_16, word % 65536 * 2), rc)
			buffer_writeu32(out, offs, word)

			word = bit32_bxor(buffer_readu32(out, offs - 28), word)
			buffer_writeu32(out, offs + 4, word)
			word = bit32_bxor(buffer_readu32(out, offs - 24), word)
			buffer_writeu32(out, offs + 8, word)
			word = bit32_bxor(buffer_readu32(out, offs - 20), word)
			buffer_writeu32(out, offs + 12, word)

			word = bit32_bxor(buffer_readu32(out, offs - 16), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
				buffer_readu16(S_BOX_16, word % 65536 * 2))
			buffer_writeu32(out, offs + 16, word)

			word = bit32_bxor(buffer_readu32(out, offs - 12), word)
			buffer_writeu32(out, offs + 20, word)
			word = bit32_bxor(buffer_readu32(out, offs - 8), word)
			buffer_writeu32(out, offs + 24, word)
			word = bit32_bxor(buffer_readu32(out, offs - 4), word)
			buffer_writeu32(out, offs + 28, word)
			word = bit32_rrotate(word, 8)
		end
		word = bit32_bxor(buffer_readu32(out, 192), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
			buffer_readu16(S_BOX_16, word % 65536 * 2), 64)
		buffer_writeu32(out, 224, word)

		word = bit32_bxor(buffer_readu32(out, 196), word)
		buffer_writeu32(out, 228, word)
		word = bit32_bxor(buffer_readu32(out, 200), word)
		buffer_writeu32(out, 232, word)
		buffer_writeu32(out, 236, bit32_bxor(buffer_readu32(out, 204), word))
	elseif len == 24 then
		for offs = 24, 168, 24 do
			rc = rc * 2 % 229
			word = bit32_bxor(buffer_readu32(out, offs - 24), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
				buffer_readu16(S_BOX_16, word % 65536 * 2), rc)
			buffer_writeu32(out, offs, word)

			word = bit32_bxor(buffer_readu32(out, offs - 20), word)
			buffer_writeu32(out, offs + 4, word)
			word = bit32_bxor(buffer_readu32(out, offs - 16), word)
			buffer_writeu32(out, offs + 8, word)
			word = bit32_bxor(buffer_readu32(out, offs - 12), word)
			buffer_writeu32(out, offs + 12, word)
			word = bit32_bxor(buffer_readu32(out, offs - 8), word)
			buffer_writeu32(out, offs + 16, word)
			word = bit32_bxor(buffer_readu32(out, offs - 4), word)
			buffer_writeu32(out, offs + 20, word)
			word = bit32_rrotate(word, 8)
		end
		word = bit32_bxor(buffer_readu32(out, 168), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
			buffer_readu16(S_BOX_16, word % 65536 * 2), 128)
		buffer_writeu32(out, 192, word)

		word = bit32_bxor(buffer_readu32(out, 172), word)
		buffer_writeu32(out, 196, word)
		word = bit32_bxor(buffer_readu32(out, 176), word)
		buffer_writeu32(out, 200, word)
		buffer_writeu32(out, 204, bit32_bxor(buffer_readu32(out, 180), word))
	else
		for offs = 16, 144, 16 do
			rc = rc * 2 % 229
			word = bit32_bxor(buffer_readu32(out, offs - 16), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
				buffer_readu16(S_BOX_16, word % 65536 * 2), rc)
			buffer_writeu32(out, offs, word)

			word = bit32_bxor(buffer_readu32(out, offs - 12), word)
			buffer_writeu32(out, offs + 4, word)
			word = bit32_bxor(buffer_readu32(out, offs - 8), word)
			buffer_writeu32(out, offs + 8, word)
			word = bit32_bxor(buffer_readu32(out, offs - 4), word)
			buffer_writeu32(out, offs + 12, word)
			word = bit32_rrotate(word, 8)
		end
		word = bit32_bxor(buffer_readu32(out, 144), buffer_readu16(S_BOX_16, math_floor(word / 65536) * 2) * 65536 +
			buffer_readu16(S_BOX_16, word % 65536 * 2), 54)
		buffer_writeu32(out, 160, word)

		word = bit32_bxor(buffer_readu32(out, 148), word)
		buffer_writeu32(out, 164, word)
		word = bit32_bxor(buffer_readu32(out, 152), word)
		buffer_writeu32(out, 168, word)
		buffer_writeu32(out, 172, bit32_bxor(buffer_readu32(out, 156), word))
	end
	return out
end


local function encryptBlock(keym: buffer, lenm: number, text: buffer, offs: number, out: buffer, offt: number): ()
	local b0 = 	bit32_bxor(buffer_readu8(text, offs), buffer_readu8(keym, 0))
	local b1 = 	bit32_bxor(buffer_readu8(text, offs + 1), buffer_readu8(keym, 1))
	local b2 = 	bit32_bxor(buffer_readu8(text, offs + 2), buffer_readu8(keym, 2))
	local b3 =	bit32_bxor(buffer_readu8(text, offs + 3), buffer_readu8(keym, 3))
	local b4 =	bit32_bxor(buffer_readu8(text, offs + 4), buffer_readu8(keym, 4))
	local b5 =	bit32_bxor(buffer_readu8(text, offs + 5), buffer_readu8(keym, 5))
	local b6 =	bit32_bxor(buffer_readu8(text, offs + 6), buffer_readu8(keym, 6))
	local b7 =	bit32_bxor(buffer_readu8(text, offs + 7), buffer_readu8(keym, 7))
	local b8 =	bit32_bxor(buffer_readu8(text, offs + 8), buffer_readu8(keym, 8))
	local b9 =	bit32_bxor(buffer_readu8(text, offs + 9), buffer_readu8(keym, 9))
	local b10 =	bit32_bxor(buffer_readu8(text, offs + 10), buffer_readu8(keym, 10))
	local b11 = bit32_bxor(buffer_readu8(text, offs + 11), buffer_readu8(keym, 11))
	local b12 = bit32_bxor(buffer_readu8(text, offs + 12), buffer_readu8(keym, 12))
	local b13 = bit32_bxor(buffer_readu8(text, offs + 13), buffer_readu8(keym, 13))
	local b14 = bit32_bxor(buffer_readu8(text, offs + 14), buffer_readu8(keym, 14))
	local b15 = bit32_bxor(buffer_readu8(text, offs + 15), buffer_readu8(keym, 15))

	local i0 = b0 * 256 + b5; 	local i1 = b5 * 256 + b10;	local i2 = b10 * 256 + b15; local i3 = b15 * 256 + b0
	local i4 = b4 * 256 + b9; 	local i5 = b9 * 256 + b14;	local i6 = b14 * 256 + b3; 	local i7 = b3 * 256 + b4
	local i8 = b8 * 256 + b13; 	local i9 = b13 * 256 + b2;	local i10 = b2 * 256 + b7; 	local i11 = b7 * 256 + b8
	local i12 = b12 * 256 + b1; local i13 = b1 * 256 + b6;	local i14 = b6 * 256 + b11; local i15 = b11 * 256 + b12

	for offs = 16, lenm, 16 do

		b0 =	bit32_bxor(buffer_readu8(S_MIX0, i0), buffer_readu8(S_MIX1, i2), buffer_readu8(keym, offs))
		b1 =	bit32_bxor(buffer_readu8(S_MIX0, i1), buffer_readu8(S_MIX1, i3), buffer_readu8(keym, offs + 1))
		b2 =	bit32_bxor(buffer_readu8(S_MIX0, i2), buffer_readu8(S_MIX1, i0), buffer_readu8(keym, offs + 2))
		b3 =	bit32_bxor(buffer_readu8(S_MIX0, i3), buffer_readu8(S_MIX1, i1), buffer_readu8(keym, offs + 3))
		b4 =	bit32_bxor(buffer_readu8(S_MIX0, i4), buffer_readu8(S_MIX1, i6), buffer_readu8(keym, offs + 4))
		b5 =	bit32_bxor(buffer_readu8(S_MIX0, i5), buffer_readu8(S_MIX1, i7), buffer_readu8(keym, offs + 5))
		b6 =	bit32_bxor(buffer_readu8(S_MIX0, i6), buffer_readu8(S_MIX1, i4), buffer_readu8(keym, offs + 6))
		b7 =	bit32_bxor(buffer_readu8(S_MIX0, i7), buffer_readu8(S_MIX1, i5), buffer_readu8(keym, offs + 7))
		b8 =	bit32_bxor(buffer_readu8(S_MIX0, i8), buffer_readu8(S_MIX1, i10), buffer_readu8(keym, offs + 8))
		b9 =	bit32_bxor(buffer_readu8(S_MIX0, i9), buffer_readu8(S_MIX1, i11), buffer_readu8(keym, offs + 9))
		b10 =	bit32_bxor(buffer_readu8(S_MIX0, i10), buffer_readu8(S_MIX1, i8), buffer_readu8(keym, offs + 10))
		b11 =	bit32_bxor(buffer_readu8(S_MIX0, i11), buffer_readu8(S_MIX1, i9), buffer_readu8(keym, offs + 11))
		b12 =	bit32_bxor(buffer_readu8(S_MIX0, i12), buffer_readu8(S_MIX1, i14), buffer_readu8(keym, offs + 12))
		b13 =	bit32_bxor(buffer_readu8(S_MIX0, i13), buffer_readu8(S_MIX1, i15), buffer_readu8(keym, offs + 13))
		b14 =	bit32_bxor(buffer_readu8(S_MIX0, i14), buffer_readu8(S_MIX1, i12), buffer_readu8(keym, offs + 14))
		b15 =	bit32_bxor(buffer_readu8(S_MIX0, i15), buffer_readu8(S_MIX1, i13), buffer_readu8(keym, offs + 15))

		i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15 = b0 * 256 + b5, b5 * 256 + b10, b10 * 256 + b15, b15 * 256 + b0, b4 * 256 + b9, b9 * 256 + b14, b14 * 256 + b3, b3 * 256 + b4, b8 * 256 + b13, b13 * 256 + b2, b2 * 256 + b7, b7 * 256 + b8, b12 * 256 + b1, b1 * 256 + b6, b6 * 256 + b11, b11 * 256 + b12
	end

	buffer_writeu32(out, offt, bit32_bxor(buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i15), buffer_readu8(S_MIX1, i13),
		buffer_readu8(keym, lenm + 31)) * 512 + bit32_bxor(buffer_readu8(S_MIX0, i10), buffer_readu8(S_MIX1, i8), buffer_readu8(keym, lenm + 26)) * 2)
			* 65536 + buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i5), buffer_readu8(S_MIX1, i7), buffer_readu8(keym, lenm + 21)) * 512 +
				bit32_bxor(buffer_readu8(S_MIX0, i0), buffer_readu8(S_MIX1, i2), buffer_readu8(keym, lenm + 16)) * 2), buffer_readu32(keym, lenm + 32)))
	buffer_writeu32(out, offt + 4, bit32_bxor(buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i3), buffer_readu8(S_MIX1, i1),
		buffer_readu8(keym, lenm + 19)) * 512 + bit32_bxor(buffer_readu8(S_MIX0, i14), buffer_readu8(S_MIX1, i12), buffer_readu8(keym, lenm + 30)) * 2)
			* 65536 + buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i9), buffer_readu8(S_MIX1, i11), buffer_readu8(keym, lenm + 25)) * 512 +
				bit32_bxor(buffer_readu8(S_MIX0, i4), buffer_readu8(S_MIX1, i6), buffer_readu8(keym, lenm + 20)) * 2), buffer_readu32(keym, lenm + 36)))
	buffer_writeu32(out, offt + 8, bit32_bxor(buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i7), buffer_readu8(S_MIX1, i5),
		buffer_readu8(keym, lenm + 23)) * 512 + bit32_bxor(buffer_readu8(S_MIX0, i2), buffer_readu8(S_MIX1, i0), buffer_readu8(keym, lenm + 18)) * 2)
			* 65536 + buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i13), buffer_readu8(S_MIX1, i15), buffer_readu8(keym, lenm + 29)) * 512 +
				bit32_bxor(buffer_readu8(S_MIX0, i8), buffer_readu8(S_MIX1, i10), buffer_readu8(keym, lenm + 24)) * 2), buffer_readu32(keym, lenm + 40)))
	buffer_writeu32(out, offt + 12, bit32_bxor(buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i11), buffer_readu8(S_MIX1, i9),
		buffer_readu8(keym, lenm + 27)) * 512 + bit32_bxor(buffer_readu8(S_MIX0, i6), buffer_readu8(S_MIX1, i4), buffer_readu8(keym, lenm + 22)) * 2)
			* 65536 + buffer_readu16(S_BOX_16, bit32_bxor(buffer_readu8(S_MIX0, i1), buffer_readu8(S_MIX1, i3), buffer_readu8(keym, lenm + 17)) * 512 +
				bit32_bxor(buffer_readu8(S_MIX0, i12), buffer_readu8(S_MIX1, i14), buffer_readu8(keym, lenm + 28)) * 2), buffer_readu32(keym, lenm + 44)))
end

local function decryptBlock(keym: buffer, lenm: number, ciph: buffer, offs: number, out: buffer, offt: number): ()
	local b0 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs) * 256 + buffer_readu8(keym, lenm + 32)), buffer_readu8(keym, lenm + 16))
	local b1 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 13) * 256 + buffer_readu8(keym, lenm + 45)), buffer_readu8(keym, lenm + 17))
	local b2 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 10) * 256 + buffer_readu8(keym, lenm + 42)), buffer_readu8(keym, lenm + 18))
	local b3 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 7) * 256 + buffer_readu8(keym, lenm + 39)), buffer_readu8(keym, lenm + 19))
	local b4 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 4) * 256 + buffer_readu8(keym, lenm + 36)), buffer_readu8(keym, lenm + 20))
	local b5 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 1) * 256 + buffer_readu8(keym, lenm + 33)), buffer_readu8(keym, lenm + 21))
	local b6 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 14) * 256 + buffer_readu8(keym, lenm + 46)), buffer_readu8(keym, lenm + 22))
	local b7 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 11) * 256 + buffer_readu8(keym, lenm + 43)), buffer_readu8(keym, lenm + 23))
	local b8 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 8) * 256 + buffer_readu8(keym, lenm + 40)), buffer_readu8(keym, lenm + 24))
	local b9 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 5) * 256 + buffer_readu8(keym, lenm + 37)), buffer_readu8(keym, lenm + 25))
	local b10 = bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 2) * 256 + buffer_readu8(keym, lenm + 34)), buffer_readu8(keym, lenm + 26))
	local b11 = bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 15) * 256 + buffer_readu8(keym, lenm + 47)), buffer_readu8(keym, lenm + 27))
	local b12 = bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 12) * 256 + buffer_readu8(keym, lenm + 44)), buffer_readu8(keym, lenm + 28))
	local b13 = bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 9) * 256 + buffer_readu8(keym, lenm + 41)), buffer_readu8(keym, lenm + 29))
	local b14 = bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 6) * 256 + buffer_readu8(keym, lenm + 38)), buffer_readu8(keym, lenm + 30))
	local b15 = bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(ciph, offs + 3) * 256 + buffer_readu8(keym, lenm + 35)), buffer_readu8(keym, lenm + 31))

	local i0 = b0 * 256 + b1; 	local i1 = b1 * 256 + b2;	local i2 = b2 * 256 + b3; 	local i3 = b3 * 256 + b0
	local i4 = b4 * 256 + b5; 	local i5 = b5 * 256 + b6; 	local i6 = b6 * 256 + b7; 	local i7 = b7 * 256 + b4
	local i8 = b8 * 256 + b9; 	local i9 = b9 * 256 + b10; 	local i10 = b10 * 256 + b11;local i11 = b11 * 256 + b8
	local i12 = b12 * 256 + b13;local i13 = b13 * 256 + b14;local i14 = b14 * 256 + b15;local i15 = b15 * 256 + b12

	for offs = lenm, 16, - 16 do

		b0 = 	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i0) * 256 + buffer_readu8(INV_MIX1, i2)), buffer_readu8(keym, offs))
		b1 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i13) * 256 + buffer_readu8(INV_MIX1, i15)), buffer_readu8(keym, offs + 1))
		b2 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i10) * 256 + buffer_readu8(INV_MIX1, i8)), buffer_readu8(keym, offs + 2))
		b3 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i7) * 256 + buffer_readu8(INV_MIX1, i5)), buffer_readu8(keym, offs + 3))
		b4 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i4) * 256 + buffer_readu8(INV_MIX1, i6)), buffer_readu8(keym, offs + 4))
		b5 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i1) * 256 + buffer_readu8(INV_MIX1, i3)), buffer_readu8(keym, offs + 5))
		b6 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i14) * 256 + buffer_readu8(INV_MIX1, i12)), buffer_readu8(keym, offs + 6))
		b7 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i11) * 256 + buffer_readu8(INV_MIX1, i9)), buffer_readu8(keym, offs + 7))
		b8 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i8) * 256 + buffer_readu8(INV_MIX1, i10)), buffer_readu8(keym, offs + 8))
		b9 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i5) * 256 + buffer_readu8(INV_MIX1, i7)), buffer_readu8(keym, offs + 9))
		b10 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i2) * 256 + buffer_readu8(INV_MIX1, i0)), buffer_readu8(keym, offs + 10))
		b11 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i15) * 256 + buffer_readu8(INV_MIX1, i13)), buffer_readu8(keym, offs + 11))
		b12 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i12) * 256 + buffer_readu8(INV_MIX1, i14)), buffer_readu8(keym, offs + 12))
		b13 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i9) * 256 + buffer_readu8(INV_MIX1, i11)), buffer_readu8(keym, offs + 13))
		b14 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i6) * 256 + buffer_readu8(INV_MIX1, i4)), buffer_readu8(keym, offs + 14))
		b15 =	bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i3) * 256 + buffer_readu8(INV_MIX1, i1)), buffer_readu8(keym, offs + 15))

		i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15 = b0 * 256 + b1, b1 * 256 + b2, b2 * 256 + b3, b3 * 256 + b0, b4 * 256 + b5, b5 * 256 + b6, b6 * 256 + b7, b7 * 256 + b4, b8 * 256 + b9, b9 * 256 + b10, b10 * 256 + b11, b11 * 256 + b8, b12 * 256 + b13, b13 * 256 + b14, b14 * 256 + b15, b15 * 256 + b12
	end

	buffer_writeu32(out, offt, bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i7) * 256 + buffer_readu8(INV_MIX1, i5)),
		buffer_readu8(keym, 3)) * 16777216 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i10) * 256 + buffer_readu8(INV_MIX1, i8)),
		buffer_readu8(keym, 2)) * 65536 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i13) * 256 + buffer_readu8(INV_MIX1, i15)),
		buffer_readu8(keym, 1)) * 256 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i0) * 256 + buffer_readu8(INV_MIX1, i2)),
		buffer_readu8(keym, 0)))
	buffer_writeu32(out, offt + 4, bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i11) * 256 + buffer_readu8(INV_MIX1, i9)),
		buffer_readu8(keym, 7)) * 16777216 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i14) * 256 + buffer_readu8(INV_MIX1, i12)),
		buffer_readu8(keym, 6)) * 65536 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i1) * 256 + buffer_readu8(INV_MIX1, i3)),
		buffer_readu8(keym, 5)) * 256 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i4) * 256 + buffer_readu8(INV_MIX1, i6)),
		buffer_readu8(keym, 4)))
	buffer_writeu32(out, offt + 8, bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i15) * 256 + buffer_readu8(INV_MIX1, i13)),
		buffer_readu8(keym, 11)) * 16777216 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i2) * 256 + buffer_readu8(INV_MIX1, i0)),
		buffer_readu8(keym, 10)) * 65536 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i5) * 256 + buffer_readu8(INV_MIX1, i7)),
		buffer_readu8(keym, 9)) * 256 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i8) * 256 + buffer_readu8(INV_MIX1, i10)),
		buffer_readu8(keym, 8)))
	buffer_writeu32(out, offt + 12, bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i3) * 256 + buffer_readu8(INV_MIX1, i1)),
		buffer_readu8(keym, 15)) * 16777216 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i6) * 256 + buffer_readu8(INV_MIX1, i4)),
		buffer_readu8(keym, 14)) * 65536 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i9) * 256 + buffer_readu8(INV_MIX1, i11)),
		buffer_readu8(keym, 13)) * 256 + bit32_bxor(buffer_readu8(INV_S_XOR, buffer_readu8(INV_MIX0, i12) * 256 + buffer_readu8(INV_MIX1, i14)),
		buffer_readu8(keym, 12)))
end

do
	local S_BOX = 		buffer_create(256)
	local INV_S_BOX = 	buffer_create(256)

	local MUL3 = buffer_create(256)
	local MUL9 = buffer_create(256)
	local MUL11 = buffer_create(256)
	local p = 1; local q = 1; local t

	local function gfmul(a: number, b: number): number
		local p = 0

		for _ = 0, 7 do
			if b % 2 == 1 then
				p = bit32_bxor(p, a)
			end

			if a >= 128 then
				a = bit32_bxor(a * 2 % 256, 27)
			else
				a = a * 2 % 256
			end
			b = math_floor(b / 2)
		end
		return p
	end

	buffer_writeu8(S_BOX, 0, 99)
	for _ = 1, 255 do
		p = bit32_bxor(p, p * 2, if p < 128 then 0 else 27) % 256
		q = bit32_bxor(q, q * 2)
		q = bit32_bxor(q, q * 4)
		q = bit32_bxor(q, q * 16) % 256
		if q >= 128 then
			q = bit32_bxor(q, 9)
		end

		t = bit32_bxor(q, q % 128 * 2 + q / 128, q % 64 * 4 + q / 64, q % 32 * 8 + q / 32, q % 16 * 16 + q / 16, 99)
		buffer_writeu8(S_BOX, p, t)
		buffer_writeu8(INV_S_BOX, t, p)

		buffer_writeu8(MUL3, p, gfmul(3, p))
		buffer_writeu8(MUL9, p, gfmul(9, p))
		buffer_writeu8(MUL11, p, gfmul(11, p))
	end


	local pb, g2, g14, g13; t = 0
	for i = 0, 255 do
		p = buffer_readu8(S_BOX, i); pb = p * 256
		g2, g13, g14 = gfmul(2, p), gfmul(13, i), gfmul(14, i)
		for j = 0, 255 do
			q = buffer_readu8(S_BOX, j)
			buffer_writeu16(S_BOX_16, t * 2, pb + q)
			buffer_writeu8(INV_S_XOR, t, buffer_readu8(INV_S_BOX, bit32_bxor(i, j)))
			buffer_writeu8(S_MIX0, t, bit32_bxor(g2, buffer_readu8(MUL3, q)))
			buffer_writeu8(S_MIX1, t, bit32_bxor(p, q))
			buffer_writeu8(INV_MIX0, t, bit32_bxor(g14, buffer_readu8(MUL11, j)))
			buffer_writeu8(INV_MIX1, t, bit32_bxor(g13, buffer_readu8(MUL9, j)))
			t += 1
		end
	end
end

export type AesCipher = typeof(setmetatable({} :: {
	Key: string, Length: number, Mode: {FwdMode: ((input: buffer, offset: number, output: buffer, offsetOut: number) -> (),
		(input: buffer, offset: number, output: buffer, offsetOut: number) -> (), buffer, buffer, {any},...any) -> (),
		InvMode: ((input: buffer, offset: number, output: buffer, offsetOut: number) -> (),
			(input: buffer, offset: number, output: buffer, offsetOut: number) -> (), buffer, buffer, {any},...any) -> ()},
	Padding: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: boolean?}, RoundKeys: string,
	Encrypt: (self: AesCipher, plaintext: buffer | string, output: buffer?,...any) -> buffer,
	Decrypt: (self: AesCipher, ciphertext: buffer | string, output: buffer?,...any) -> buffer,
	EncryptBlock: (self: AesCipher, plaintext: buffer, offset: number, output: buffer?, offsetOut: number?) -> (),
	DecryptBlock: (self: AesCipher, ciphertext: buffer, offset: number, output: buffer?, offsetOut: number?) -> (),
	Destroy: (self: AesCipher) -> ()
}, {}))
local function newidx(_, idx)
	return error(`{idx} cannot be assigned to`)
end
local function tostr()
	return "AesCipher"
end

local modes = (function()
	local assert = assert
	local bit32_bxor = bit32.bxor
	local buffer_copy = 		buffer.copy
	local buffer_create = 		buffer.create
	local buffer_len = 			buffer.len
	local buffer_readu8 = 		buffer.readu8
	local buffer_readu32 =		buffer.readu32
	local buffer_tostring = 	buffer.tostring
	local buffer_writestring = 	buffer.writestring
	local buffer_writeu8 = 		buffer.writeu8
	local buffer_writeu32 = 	buffer.writeu32

	local math_floor = math.floor
	local math_random = math.random
	local table_freeze = table.freeze
	local string_pack = string.pack


	local ZEROES = buffer_create(16)

	local function addByteCtr(ctr: buffer, step: number, offs0: number, offs1: number, le: boolean): ()
		local byte
		if le then
			byte = buffer_readu8(ctr, offs0) + step
			buffer_writeu8(ctr, offs0, byte)
			if byte >= 256 then
				for offs = offs0 + 1, offs1 do
					byte = buffer_readu8(ctr, offs) + 1
					buffer_writeu8(ctr, offs, byte)
					if byte < 256 then
						break
					end
				end
			end
		else
			byte = buffer_readu8(ctr, offs1) + step
			buffer_writeu8(ctr, offs1, byte)
			if byte >= 256 then
				for offs = offs1 - 1, offs0, - 1 do
					byte = buffer_readu8(ctr, offs) + 1
					buffer_writeu8(ctr, offs, byte)
					if byte < 256 then
						break
					end
				end
			end
		end
	end

	local modes = {}

	modes.ECB = table_freeze({
		FwdMode = function(encp, _, text, out)
			local len = buffer_len(text) - 16
			assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
			for offs = 0, len, 16 do
				encp(text, offs, out, offs)
			end
		end,
		InvMode = function(_, decp, ciph, out)
			local len = buffer_len(ciph) - 16
			assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
			for offs = 0, len, 16 do
				decp(ciph, offs, out, offs)
			end
		end
	})

	modes.CBC = table_freeze({
		FwdMode = function(encp, _, text, out, _, iv)
			local len = buffer_len(text) - 16
			assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
			iv = iv or ZEROES
			assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
			buffer_writeu32(out, 0, bit32_bxor(buffer_readu32(text, 0), buffer_readu32(iv, 0)))
			buffer_writeu32(out, 4, bit32_bxor(buffer_readu32(text, 4), buffer_readu32(iv, 4)))
			buffer_writeu32(out, 8, bit32_bxor(buffer_readu32(text, 8), buffer_readu32(iv, 8)))
			buffer_writeu32(out, 12, bit32_bxor(buffer_readu32(text, 12), buffer_readu32(iv, 12)))
			encp(out, 0, out, 0)
			for offs = 16, len, 16 do
				buffer_writeu32(out, offs, bit32_bxor(buffer_readu32(text, offs), buffer_readu32(out, offs - 16)))
				buffer_writeu32(out, offs + 4, bit32_bxor(buffer_readu32(text, offs + 4), buffer_readu32(out, offs - 12)))
				buffer_writeu32(out, offs + 8, bit32_bxor(buffer_readu32(text, offs + 8), buffer_readu32(out, offs - 8)))
				buffer_writeu32(out, offs + 12, bit32_bxor(buffer_readu32(text, offs + 12), buffer_readu32(out, offs - 4)))
				encp(out, offs, out, offs)
			end
		end,
		InvMode = function(_, decp, ciph, out, _, iv)
			local len = buffer_len(ciph) - 16
			assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
			iv = iv or ZEROES
			assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
			local w0 = buffer_readu32(ciph, 0); local w1 = buffer_readu32(ciph, 4)
			local w2 = buffer_readu32(ciph, 8); local w3 = buffer_readu32(ciph, 12)
			local w4, w5, w6, w7
			decp(ciph, 0, out, 0)
			buffer_writeu32(out, 0, bit32_bxor(buffer_readu32(out, 0), buffer_readu32(iv, 0)))
			buffer_writeu32(out, 4, bit32_bxor(buffer_readu32(out, 4), buffer_readu32(iv, 4)))
			buffer_writeu32(out, 8, bit32_bxor(buffer_readu32(out, 8), buffer_readu32(iv, 8)))
			buffer_writeu32(out, 12, bit32_bxor(buffer_readu32(out, 12), buffer_readu32(iv, 12)))
			for offs = 16, len, 16 do
				w4 = buffer_readu32(ciph, offs)
				w5 = buffer_readu32(ciph, offs + 4)
				w6 = buffer_readu32(ciph, offs + 8)
				w7 = buffer_readu32(ciph, offs + 12)
				decp(ciph, offs, out, offs)
				buffer_writeu32(out, offs, bit32_bxor(buffer_readu32(out, offs), w0))
				buffer_writeu32(out, offs + 4, bit32_bxor(buffer_readu32(out, offs + 4), w1))
				buffer_writeu32(out, offs + 8, bit32_bxor(buffer_readu32(out, offs + 8), w2))
				buffer_writeu32(out, offs + 12, bit32_bxor(buffer_readu32(out, offs + 12), w3))
				w0, w1, w2, w3 = w4, w5, w6, w7
			end
		end
	})

	modes.PCBC = table_freeze({
		FwdMode = function(encp, _, text, out, _, iv)
			local len = buffer_len(text) - 16
			assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
			iv = iv or ZEROES
			assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
			local w0 = buffer_readu32(text, 0); local w1 = buffer_readu32(text, 4)
			local w2 = buffer_readu32(text, 8); local w3 = buffer_readu32(text, 12)
			local w4, w5, w6, w7
			buffer_writeu32(out, 0, bit32_bxor(w0, buffer_readu32(iv, 0)))
			buffer_writeu32(out, 4, bit32_bxor(w1, buffer_readu32(iv, 4)))
			buffer_writeu32(out, 8, bit32_bxor(w2, buffer_readu32(iv, 8)))
			buffer_writeu32(out, 12, bit32_bxor(w3, buffer_readu32(iv, 12)))
			encp(out, 0, out, 0)
			for offs = 16, len, 16 do
				w4 = buffer_readu32(text, offs)
				w5 = buffer_readu32(text, offs + 4)
				w6 = buffer_readu32(text, offs + 8)
				w7 = buffer_readu32(text, offs + 12)
				buffer_writeu32(out, offs, bit32_bxor(w0, w4, buffer_readu32(out, offs - 16)))
				buffer_writeu32(out, offs + 4, bit32_bxor(w1, w5, buffer_readu32(out, offs - 12)))
				buffer_writeu32(out, offs + 8, bit32_bxor(w2, w6, buffer_readu32(out, offs - 8)))
				buffer_writeu32(out, offs + 12, bit32_bxor(w3, w7, buffer_readu32(out, offs - 4)))
				encp(out, offs, out, offs)
				w0, w1, w2, w3 = w4, w5, w6, w7
			end
		end,
		InvMode = function(_, decp, ciph, out, _, iv)
			local len = buffer_len(ciph) - 16
			assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
			iv = iv or ZEROES
			assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
			local w0 = buffer_readu32(ciph, 0); local w1 = buffer_readu32(ciph, 4)
			local w2 = buffer_readu32(ciph, 8); local w3 = buffer_readu32(ciph, 12)
			decp(ciph, 0, out, 0)
			local w4 = bit32_bxor(buffer_readu32(out, 0), buffer_readu32(iv, 0))
			local w5 = bit32_bxor(buffer_readu32(out, 4), buffer_readu32(iv, 4))
			local w6 = bit32_bxor(buffer_readu32(out, 8), buffer_readu32(iv, 8))
			local w7 = bit32_bxor(buffer_readu32(out, 12), buffer_readu32(iv, 12))
			local w8, w9, w10, w11
			buffer_writeu32(out, 0, w4)
			buffer_writeu32(out, 4, w5)
			buffer_writeu32(out, 8, w6)
			buffer_writeu32(out, 12, w7)
			local offp0, offp1, offp2, offp3 = 0, 4, 8, 12
			for offs = 16, len, 16 do
				offp0 += 16; offp1 += 16; offp2 += 16; offp3 += 16
				w8 = buffer_readu32(ciph, offp0)
				w9 = buffer_readu32(ciph, offp1)
				w10 = buffer_readu32(ciph, offp2)
				w11 = buffer_readu32(ciph, offp3)
				decp(ciph, offs, out, offs)
				w4 = bit32_bxor(w0, w4, buffer_readu32(out, offp0))
				w5 = bit32_bxor(w1, w5, buffer_readu32(out, offp1))
				w6 = bit32_bxor(w2, w6, buffer_readu32(out, offp2))
				w7 = bit32_bxor(w3, w7, buffer_readu32(out, offp3))
				w0, w1, w2, w3 = w8, w9, w10, w11
				buffer_writeu32(out, offp0, w4)
				buffer_writeu32(out, offp1, w5)
				buffer_writeu32(out, offp2, w6)
				buffer_writeu32(out, offp3, w7)
			end
		end
	})

	local function cfbFwd(encp, _, text, out, options: {CommonTemp: buffer, SegmentSize: number}, iv)
		local segm = options.SegmentSize
		local len = buffer_len(text)
		assert(len % segm == 0, "Input length must be a multiple of segment size")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		local temp = options.CommonTemp or buffer_create(31)
		if len == segm then
			encp(iv, 0, temp, 0)
			for offs = 0, segm - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, offs)))
			end
		else
			local last = len - segm; local offb = 16 - segm
			local i
			encp(iv, 0, temp, 0)
			for offs = 0, segm - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, offs)))
			end
			buffer_copy(temp, 0, iv, segm, offb)
			buffer_copy(temp, offb, out, 0, segm)
			for offs = segm, last - segm, segm do
				i = 0
				buffer_copy(temp, 16, temp, segm, offb)
				encp(temp, 0, temp, 0)
				for offs = offs, offs + segm - 1 do
					buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, i)))
					i += 1
				end
				buffer_copy(temp, 0, temp, 16, offb)
				buffer_copy(temp, offb, out, offs, segm)
			end
			encp(temp, 0, temp, 0)
			i = 0
			for offs = last, len - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(text, offs), buffer_readu8(temp, i)))
				i += 1
			end
		end
	end

	local function cfbInv(encp, _, ciph, out, options: {CommonTemp: buffer, SegmentSize: number}, iv)
		local len = buffer_len(ciph)
		local segm = options.SegmentSize
		assert(len % segm == 0, "Input length must be a multiple of segment size")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		local temp = options.CommonTemp or buffer_create(31)
		if len == segm then
			encp(iv, 0, temp, 0)
			for offs = 0, segm - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, offs)))
			end
		else
			local last = len - segm; local offb = 16 - segm
			local i
			encp(iv, 0, temp, 0)
			for offs = 0, segm - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, offs)))
			end
			buffer_copy(temp, 0, iv, segm, offb)
			buffer_copy(temp, offb, ciph, 0, segm)
			for offs = segm, last - segm, segm do
				i = 0
				buffer_copy(temp, 16, temp, segm, offb)
				encp(temp, 0, temp, 0)
				for offs = offs, offs + segm - 1 do
					buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, i)))
					i += 1
				end
				buffer_copy(temp, 0, temp, 16, offb)
				buffer_copy(temp, offb, ciph, offs, segm)
			end
			encp(temp, 0, temp, 0)
			i = 0
			for offs = last, len - 1 do
				buffer_writeu8(out, offs, bit32_bxor(buffer_readu8(ciph, offs), buffer_readu8(temp, i)))
				i += 1
			end
		end
	end

	local function ofbMode(encp, _, text: buffer, out: buffer, _, iv: buffer)
		local len = buffer_len(text) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		iv = iv or ZEROES
		assert(buffer_len(iv) == 16, "Initialization vector must be 16 bytes long")
		local w0 = buffer_readu32(text, 0); local w1 = buffer_readu32(text, 4)
		local w2 = buffer_readu32(text, 8); local w3 = buffer_readu32(text, 12)
		encp(iv, 0, out, 0)
		w0 = bit32_bxor(w0, buffer_readu32(out, 0))
		w1 = bit32_bxor(w1, buffer_readu32(out, 4))
		w2 = bit32_bxor(w2, buffer_readu32(out, 8))
		w3 = bit32_bxor(w3, buffer_readu32(out, 12))
		local w4, w5, w6, w7
		for offs = 16, len, 16 do
			w4 = buffer_readu32(text, offs)
			w5 = buffer_readu32(text, offs + 4)
			w6 = buffer_readu32(text, offs + 8)
			w7 = buffer_readu32(text, offs + 12)
			encp(out, offs - 16, out, offs)
			buffer_writeu32(out, offs - 16, w0)
			buffer_writeu32(out, offs - 12, w1)
			buffer_writeu32(out, offs - 8, w2)
			buffer_writeu32(out, offs - 4, w3)
			w0 = bit32_bxor(w4, buffer_readu32(out, offs))
			w1 = bit32_bxor(w5, buffer_readu32(out, offs + 4))
			w2 = bit32_bxor(w6, buffer_readu32(out, offs + 8))
			w3 = bit32_bxor(w7, buffer_readu32(out, offs + 12))
		end
		buffer_writeu32(out, len, w0)
		buffer_writeu32(out, len + 4, w1)
		buffer_writeu32(out, len + 8, w2)
		buffer_writeu32(out, len + 12, w3)
	end
	modes.OFB = table_freeze({
		FwdMode = ofbMode, InvMode = ofbMode
	})

	local function ctrMode(encp, _, text, out, options: {CommonTemp: buffer, InitValue: string, Prefix: string, Suffix: string,
		Step: number, LittleEndian: boolean})
		local len = buffer_len(text) - 16
		assert(len % 16 == 0, "Input length must be a multiple of 16 bytes")
		local temp = options.CommonTemp
		local init = options.InitValue; local pre = options.Prefix
		local suf = options.Suffix; local step = options.Step; local le = options.LittleEndian
		local offs0 = #pre; local offs1 = offs0 + #init - 1
		buffer_writestring(temp, 0, pre)
		buffer_writestring(temp, offs0, init)
		buffer_writestring(temp, offs1 + 1, suf)
		local w0 = buffer_readu32(text, 0); local w1 = buffer_readu32(text, 4)
		local w2 = buffer_readu32(text, 8); local w3 = buffer_readu32(text, 12)
		encp(temp, 0, out, 0)
		buffer_writeu32(out, 0, bit32_bxor(buffer_readu32(out, 0), w0))
		buffer_writeu32(out, 4, bit32_bxor(buffer_readu32(out, 4), w1))
		buffer_writeu32(out, 8, bit32_bxor(buffer_readu32(out, 8), w2))
		buffer_writeu32(out, 12, bit32_bxor(buffer_readu32(out, 12), w3))
		for offs = 16, len, 16 do
			w0 = buffer_readu32(text, offs)
			w1 = buffer_readu32(text, offs + 4)
			w2 = buffer_readu32(text, offs + 8)
			w3 = buffer_readu32(text, offs + 12)
			addByteCtr(temp, step, offs0, offs1, le)
			encp(temp, 0, out, offs)
			buffer_writeu32(out, offs, bit32_bxor(w0, buffer_readu32(out, offs)))
			buffer_writeu32(out, offs + 4, bit32_bxor(w1, buffer_readu32(out, offs + 4)))
			buffer_writeu32(out, offs + 8, bit32_bxor(w2, buffer_readu32(out, offs + 8)))
			buffer_writeu32(out, offs + 12, bit32_bxor(w3, buffer_readu32(out, offs + 12)))
		end
	end

	local meta = {
		__index = function(_, idx: "CFB" | "CTR"): {}?
			return if idx == "CFB" then {
				FwdMode = cfbFwd, InvMode = cfbInv,
				SegmentSize = 16,
				CommonTemp = buffer_create(31)
			} elseif idx == "CTR" then {
					FwdMode = ctrMode, InvMode = ctrMode,
					InitValue = string_pack("I2I2I2I2I2I2I2I2", math_random(0, 65535), math_random(0, 65535), math_random(0, 65535),
						math_random(0, 65535), math_random(0, 65535), math_random(0, 65535), math_random(0, 65535), math_random(0, 65535)),
					Prefix = "", Suffix = "", Step = 1, LittleEndian = false,
					CommonTemp = buffer_create(16)
				} else nil
		end,
		__newindex = function()
		end
	}
	setmetatable(modes, meta)
	modes.CFB = {} :: {FwdMode: typeof(cfbFwd), InvMode: typeof(cfbInv), CommonTemp: buffer, SegmentSize: number}
	modes.CTR = {} :: {FwdMode: typeof(ctrMode), InvMode: typeof(ctrMode), CommonTemp: buffer, InitValue: string, Prefix: string, Suffix: string,
		Step: number, LittleEndian: boolean}
	table_freeze(modes)
	meta.__metatable = "This metatable is locked"
	return modes

end)()

local pads = (function()

	local assert = assert
	local error = error

	local buffer_copy = 	buffer.copy
	local buffer_create = 	buffer.create
	local buffer_fill = 	buffer.fill
	local buffer_len = 		buffer.len
	local buffer_readu8 = 	buffer.readu8
	local buffer_writeu8 = 	buffer.writeu8
	local math_random = math.random
	local table_freeze = table.freeze
	local pads = {}

	local function nonPad(text)
		return text
	end
	pads.None = table_freeze({
		Pad = nonPad, Unpad = nonPad,
		Overwrite = false
	})

	local function anxPad(text, out, segm)
		local len = buffer_len(text)
		local offs = len - len % segm
		if out then
			assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
			local offb = segm - len % segm
			buffer_copy(out, 0, text, 0, len)
			buffer_fill(out, len, 0, offb - 1)
			buffer_writeu8(out, offs + segm - 1, offb)
		else
			offs += segm
			out = buffer_create(offs)
			buffer_copy(out, 0, text, 0, len)
			buffer_writeu8(out, offs - 1, segm - len % segm)
		end
		return out
	end
	local function anxUnpad(text, out, segm)
		local len = buffer_len(text)
		local offs = buffer_readu8(text, len - 1)
		local offb = len - offs
		assert(0 < offs and offs <= segm, "Got unexpected padding")
		for offs = offb, len - 2 do
			if buffer_readu8(text, offs) ~= 0 then
				error("Got unexpected padding")
			end
		end
		if out then
			assert(buffer_len(out) >= offb, "Output buffer out of bounds")
		else
			out = buffer_create(offb)
		end
		buffer_copy(out, 0, text, 0, offb)
		return out
	end

	local function i10Pad(text, out, segm)
		local len = buffer_len(text)
		local offs = len - len % segm
		if out then
			assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
		else
			out = buffer_create(offs + segm)
		end
		buffer_copy(out, 0, text, 0, len)
		for offs = len, offs + segm - 2 do
			buffer_writeu8(out, offs, math_random(0, 255))
		end
		buffer_writeu8(out, offs + segm - 1, segm - len % segm)
		return out
	end

	local function i10Unpad(text, out, segm)
		local len = buffer_len(text)
		local offs = buffer_readu8(text, len - 1)
		local offb = len - offs
		assert(0 < offs and offs <= segm, "Got unexpected padding")
		if out then
			assert(buffer_len(out) >= offb, "Output buffer out of bounds")
		else
			out = buffer_create(offb)
		end
		buffer_copy(out, 0, text, 0, offb)
		return out
	end

	local function pksPad(text, out, segm)
		local len = buffer_len(text)
		local offs = len - len % segm
		if out then
			assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
		else
			out = buffer_create(offs + segm)
		end
		local offb = segm - len % segm
		buffer_copy(out, 0, text, 0, len)
		buffer_fill(out, len, offb, offb)
		return out
	end

	local function pksUnpad(text, out, segm)
		local len = buffer_len(text)
		local offs = buffer_readu8(text, len - 1)
		local offb = len - offs
		assert(0 < offs and offs <= segm, "Got unexpected padding")
		for offb = offb, len - 2 do
			if buffer_readu8(text, offb) ~= offs then
				error("Got unexpected padding")
			end
		end
		if out then
			assert(buffer_len(out) >= offb, "Output buffer out of bounds")
		else
			out = buffer_create(offb)
		end
		buffer_copy(out, 0, text, 0, offb)
		return out
	end

	local function ii7Pad(text, out, segm)
		local len = buffer_len(text)
		if out then
			assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
			buffer_fill(out, len + 1, 0, segm - len % segm - 1)
		else
			out = buffer_create(len + segm - len % segm)
		end
		buffer_copy(out, 0, text, 0, len)
		buffer_writeu8(out, len, 128)
		return out
	end
	local function ii7Unpad(text, out, segm)
		local len = buffer_len(text) - 1
		local byte
		for offs = len, len - segm, - 1 do
			byte = buffer_readu8(text, offs)
			if byte == 128 then
				if out then
					assert(buffer_len(out) >= offs, "Output buffer out of bounds")
				else
					out = buffer_create(offs)
				end
				buffer_copy(out, 0, text, 0, offs)
				return out
			else
				assert(byte == 0, "Got unexpected padding")
			end
		end
		error("Got unexpected padding")
		return buffer_create(0)
	end




	local function zroPad(text, out, segm)
		local len = buffer_len(text)
		if out then
			assert(buffer_len(out) >= len + segm, "Output buffer out of bounds")
			buffer_fill(out, len, 0, segm - len % segm)
		else
			out = buffer_create(len + segm - len % segm)
		end
		buffer_copy(out, 0, text, 0, len)
		return out
	end
	local function zroUnpad(text, out, segm)
		local len = buffer_len(text) - 1
		local byte
		for offs = len, len - segm, - 1 do
			byte = buffer_readu8(text, offs)
			if byte == 0 then
				offs += 1
				if out then
					assert(buffer_len(out) >= offs, "Output buffer out of bounds")
				else
					out = buffer_create(offs)
				end
				buffer_copy(out, 0, text, 0, offs)
				return out
			end
		end
		buffer_copy(out, 0, text, 0, len - segm - 1)
		return out
	end

	local meta = {
		__index = function(_, idx: "AnsiX923" | "Iso10126" | "Pkcs7" | "Iso7816_4" | "Zero"): {}?
			return if idx == "AnsiX923" then {
				Pad = anxPad, Unpad = anxPad,
				Overwrite = nil
			} elseif idx == "Iso10126" then {
					Pad = i10Pad, Unpad = i10Unpad,
					Overwrite = nil
				} elseif idx == "Pkcs7" then {
					Pad = pksPad, Unpad = pksUnpad,
					Overwrite = nil
				} elseif idx == "Iso7816_4" then {
					Pad = ii7Pad, Unpad = ii7Unpad,
					Overwrite = nil
				} elseif idx == "Zero" then {
					Pad = zroPad, Unpad = zroUnpad,
					Overwrite = nil
				} else nil
		end,
		__newindex = function() end
	}
	setmetatable(pads, meta)
	pads.AnsiX923 = 	{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
	pads.Iso10126 = 	{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
	pads.Pkcs7 = 		{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
	pads.Iso7816_4 = 	{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
	pads.Zero = 		{} :: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: nil | boolean}
	table_freeze(pads)
	meta.__metatable = "This metatable is locked"
	return pads
end)()

local function expandKey(key: buffer | string, output: buffer?): buffer
	local raw = typeof(key) == "buffer"
	local len = if raw then buffer_len(key :: buffer) else #(key :: string)
	local lenx = if len == 32 then 240 elseif len == 24 then 208 elseif len == 16 then 176 else error("Key must be either 16, 24 or 32 bytes long")
	return keySchedule(key, len, output or buffer_create(lenx :: number), raw)
end

local function fromKey(roundKeys: buffer, mode: {FwdMode: ((input: buffer, offset: number, output: buffer, offsetOut: number) -> (),
	(input: buffer, offset: number, output: buffer, offsetOut: number) -> (), buffer, buffer, {[string]: any},...any) -> (),
	InvMode: ((input: buffer, offset: number, output: buffer, offsetOut: number) -> (),
		(input: buffer, offset: number, output: buffer, offsetOut: number) -> (), buffer, buffer, {[string]: any},...any) -> ()}?,
	pad: {Pad: (buffer, buffer?, number) -> buffer, Unpad: (buffer, buffer?, number) -> buffer, Overwrite: boolean?}?): AesCipher
	local len: number? = buffer_len(roundKeys)
	local lenm: number?; local key: string?
	local keyst: string? = buffer_tostring(roundKeys)
	if len == 240 then
		lenm = 192
		key = string_sub(keyst :: string, 1, 32)
	elseif len == 208 then
		lenm = 160
		key = string_sub(keyst :: string, 1, 24)
	elseif len == 176 then
		lenm = 128
		key = string_sub(keyst :: string, 1, 16)
	else
		error("Round keys must be either 240, 208 or 128 bytes long")
	end

	local keym: buffer? = roundKeys
	local mode: any = mode or modes.ECB
	local fwd = mode.FwdMode; local inv = mode.InvMode; local segm = mode.SegmentSize or 16
	local pad: any = pad or pads.Pkcs7
	local pd = pad.Pad; local upd = pad.Unpad
	local cipher = newproxy(true) :: AesCipher
	local meta = getmetatable(cipher)

	local function encp(plaintext, offset, output, offsetOut)
		encryptBlock(keym :: buffer, lenm :: number, plaintext, offset, output, offsetOut)
	end
	local function decp(ciphertext, offset, output, offsetOut)
		decryptBlock(keym :: buffer, lenm :: number, ciphertext, offset, output, offsetOut)
	end
	local function enc(self: AesCipher, plaintext, output, ...)
		local raw = typeof(plaintext)
		local text = if raw == "buffer" then plaintext :: buffer elseif raw == "string" then buffer_fromstring(plaintext)
			else error(`Unable to cast {raw} to buffer`)
		output = typeof(output) == "buffer" and output
		if self ~= cipher then
			return self:Encrypt(text, output :: buffer, ...)
		elseif lenm then
			local out = pd(text, output, segm)
			fwd(encp, decp, if pad.Overwrite == false then text else out, out, mode, ...)
			return out
		else
			error("AesCipher object's already destroyed")
			return buffer_create(0)
		end
	end
	local function encb(self: AesCipher, plaintext, offset, output, offsetOut)
		if self ~= cipher then
			self:EncryptBlock(plaintext, offset, output, offsetOut)
		elseif lenm then
			encryptBlock(keym :: buffer, lenm :: number, plaintext, offset, output or plaintext, offsetOut or offset)
		else
			error("AesCipher object's already destroyed")
		end
	end
	local function dec(self: AesCipher, ciphertext, output, ...)
		local raw = typeof(ciphertext)
		local ciph = if raw == "buffer" then ciphertext :: buffer elseif raw == "string" then buffer_fromstring(ciphertext)
			else error(`Unable to cast {raw} to buffer`)
		output = typeof(output) == "buffer" and output
		if self ~= cipher then
			return self:Decrypt(ciph, output :: buffer, ...)
		elseif lenm then
			local ovw = pad.Overwrite
			local text = if ovw == nil then buffer_create(buffer_len(ciph)) elseif ovw then ciph else output or buffer_create(buffer_len(ciph))
			inv(encp, decp, ciph, text, mode, ...)
			return upd(text, output, segm)
		else
			error("AesCipher object's already destroyed")
			return buffer_create(0)
		end
	end
	local function decb(self: AesCipher, ciphertext, offset, output, offsetOut)
		if self ~= cipher then
			self:DecryptBlock(ciphertext, offset, output, offsetOut)
		elseif lenm then
			decryptBlock(keym :: buffer, lenm :: number, ciphertext, offset, output or ciphertext, offsetOut or offset)
		else
			error("AesCipher object's already destroyed")
		end
	end
	local function destroy(self: AesCipher): ()
		if self ~= cipher then
			self:Destroy()
		elseif lenm then
			keyst, keym, lenm, fwd, inv, mode, pad, key, len = nil, nil, nil, nil, nil, nil, nil, nil, nil
		else
			error("AesCipher object's already destroyed")
		end
	end

	meta.__index = function(_, idx)
		return if idx == "Encrypt" then enc elseif idx == "Decrypt" then dec elseif idx == "EncryptBlock" then encb elseif idx == "DecryptBlock" then decb
			elseif idx == "Destroy" then destroy elseif lenm then (if idx == "Key" then key elseif idx == "RoundKeys" then keyst
				elseif idx == "Mode" then mode elseif idx == "Padding" then pad elseif idx == "Length" then len
				else error(`{idx} is not a valid member of AesCipher`)) else error("AesCipher object's already destroyed")
	end
	meta.__newindex = newidx
	meta.__tostring = tostr
	meta.__len = function(): number
		return len or error("AesCipher object's destroyed")
	end
	meta.__metatable = "AesCipher object: Metatable's locked"
	return cipher
end

return table.freeze({
	new = function(masterKey, mode, pad)
		return fromKey(expandKey(masterKey), mode, pad)
	end,
	expandKey = expandKey,
	fromKey = fromKey,
	modes = modes,
	pads = pads
})
]===], "@TAP/rgAES")()

local HMAC = safeLoadstring([===[
--[=[
	Cryptography library: HMAC

	Return type: string or function
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Key = buffer.fromstring("Key")
		local BlockSize = 64 -- SHA256 block length (= string.len(SHA256(...)))

		local Result = HMAC(Message, Key, SHA2.SHA256, BlockSize) -- SHA3/Blake family should have BigEndian = false
--]=]

--!strict
--!optimize 2
--!native

export type HashFunction = (...any) -> (string, buffer)

local function FromByteAndSize(Byte: number, Size: number)
	local Buffer = buffer.create(Size)
	buffer.fill(Buffer, 0, Byte)
	return Buffer
end

local function ToBigEndian(Buffer: buffer)
	for Index = 0, buffer.len(Buffer) - 1, 4 do
		buffer.writeu32(Buffer, Index, bit32.byteswap(buffer.readu32(Buffer, Index)))
	end
end

local function ConcatenateBuffers(LeftBuffer: buffer, RightBuffer: buffer)
	local LeftBufLen = buffer.len(LeftBuffer)
	local Buffer = buffer.create(LeftBufLen + buffer.len(RightBuffer))

	buffer.copy(Buffer, 0, LeftBuffer)
	buffer.copy(Buffer, LeftBufLen, RightBuffer)

	return Buffer
end

local function XORBuffer(LeftBuffer: buffer, RightBuffer: buffer)
	local Size = math.min(buffer.len(LeftBuffer), buffer.len(RightBuffer))
	local NewBuffer = buffer.create(Size)

	for Index = 0, Size - 1 do
		local LeftValue = buffer.readu8(LeftBuffer, Index)
		local RightValue = buffer.readu8(RightBuffer, Index)
		buffer.writeu8(NewBuffer, Index, bit32.bxor(LeftValue, RightValue))
	end

	return NewBuffer
end

local function ComputeBlockSizedKey(Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number, BigEndian: boolean?): buffer
	local KeyLength = buffer.len(Key)
	if KeyLength > BlockSizeBytes then
		local _, Digest = HashFunction(Key)
		if BigEndian ~= false then
			ToBigEndian(Digest)
		end

		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Digest)
		return PaddedKey
	elseif KeyLength < BlockSizeBytes then
		local PaddedKey = buffer.create(BlockSizeBytes)
		buffer.copy(PaddedKey, 0, Key)
		return PaddedKey
	end

	return Key
end

local function HMAC(Message: buffer, Key: buffer, HashFunction: HashFunction, BlockSizeBytes: number, BigEndian: boolean?): (string, buffer)
	local BlockSizedKey = ComputeBlockSizedKey(Key, HashFunction, BlockSizeBytes, BigEndian)
	local OuterPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x5C, BlockSizeBytes))
	local InnerPaddedKey = XORBuffer(BlockSizedKey, FromByteAndSize(0x36, BlockSizeBytes))
	local _, HashedMessageWithInnerKey = HashFunction(ConcatenateBuffers(InnerPaddedKey, Message))

	if BigEndian ~= false then
		ToBigEndian(HashedMessageWithInnerKey)
	end

	local FinalMessage = ConcatenateBuffers(OuterPaddedKey, HashedMessageWithInnerKey)
	return HashFunction(FinalMessage)
end

return HMAC
]===])()

local HMAC_SHA256 = safeLoadstring([===[
--[=[
	Cryptography library: SHA256

	Sizes:
		Digest: 32 bytes

	Return type: string
	Example usage:
		local Message = buffer.fromstring("Hello World")
		local Result = SHA256(Message)
--]=]

--!strict
--!optimize 2
--!native
local CONSTANTS = buffer.create(256) do -- CONSTANTS = k
	local RoundConstants = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}

	for Index, Constant in ipairs(RoundConstants) do
		local BufferOffset = (Index - 1) * 4
		buffer.writeu32(CONSTANTS, BufferOffset, Constant)
	end
end

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = -(ContentLength + 9) % 64

	local NewContentLength = ContentLength + 1 + Padding + 8
	local NewContent = buffer.create(NewContentLength)
	buffer.copy(NewContent, 0, Contents)
	buffer.writeu8(NewContent, ContentLength, 128)
	local Length8 = ContentLength * 8
	for Index = 7, 0, -1 do
		local Remainder = Length8 % 256
		buffer.writeu8(NewContent, Index + ContentLength + 1 + Padding, Remainder)
		Length8 = (Length8 - Remainder) / 256
	end

	return NewContent, NewContentLength
end

local OFFSETS = buffer.create(256)
local function DigestBlocks(Blocks: buffer, Length: number): (number, number, number, number, number, number, number, number)
	local A, B, C, D = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local E, F, G, H = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	local Offsets = OFFSETS
	local Constants = CONSTANTS

	for Offset = 0, Length - 1, 64 do
		for BlockIndex = 0, 60, 4 do
			buffer.writeu32(Offsets, BlockIndex, bit32.byteswap(buffer.readu32(Blocks, Offset + BlockIndex)))
		end

		for Index = 64, 252, 4 do
			local Sub15 = buffer.readu32(Offsets, Index - 60)
			local S0 = bit32.bxor(bit32.rrotate(Sub15, 7), bit32.rrotate(Sub15, 18), bit32.rshift(Sub15, 3))

			local Sub2 = buffer.readu32(Offsets, Index - 8)
			local S1 = bit32.bxor(bit32.rrotate(Sub2, 17), bit32.rrotate(Sub2, 19), bit32.rshift(Sub2, 10))

			local Sub7, Sub16 = buffer.readu32(Offsets, Index - 28), buffer.readu32(Offsets, Index - 64)
			buffer.writeu32(Offsets, Index, (Sub16 + S0 + Sub7 + S1))
		end

		local OldA, OldB, OldC, OldD, OldE, OldF, OldG, OldH = A, B, C, D, E, F, G, H

		for BufferIndex = 0, 252, 4 do
			local S1 = bit32.bxor(bit32.rrotate(E, 6), bit32.rrotate(E, 11), bit32.rrotate(E, 25))
			local Ch = bit32.bxor(bit32.band(E, F), bit32.band(bit32.bnot(E), G))
			local Temp1 = H + S1 + Ch + buffer.readu32(Constants, BufferIndex) + buffer.readu32(Offsets, BufferIndex)
			H, G, F, E, D = G, F, E, D + Temp1, C

			local S0 = bit32.bxor(bit32.rrotate(A, 2), bit32.rrotate(A, 13), bit32.rrotate(A, 22))
			local Maj = bit32.bxor(bit32.band(A, B), bit32.band(A, C), bit32.band(B, C))
			C, B, A = B, A, Temp1 + S0 + Maj
		end

		A, B, C, D, E, F, G, H =
			bit32.bor(A + OldA, 0),
			bit32.bor(B + OldB, 0),
			bit32.bor(C + OldC, 0),
			bit32.bor(D + OldD, 0),
			bit32.bor(E + OldE, 0),
			bit32.bor(F + OldF, 0),
			bit32.bor(G + OldG, 0),
			bit32.bor(H + OldH, 0) :: number
	end

	return A, B, C, D, E, F, G, H
end

local function SHA256(Message: buffer): (string, buffer)
	local ProcessedMessage, Length = PreProcess(Message)
	local A, B, C, D, E, F, G, H = DigestBlocks(ProcessedMessage, Length)

	local Digest = buffer.create(32)

	buffer.writeu32(Digest, 0, A)
	buffer.writeu32(Digest, 4, B)
	buffer.writeu32(Digest, 8, C)
	buffer.writeu32(Digest, 12, D)
	buffer.writeu32(Digest, 16, E)
	buffer.writeu32(Digest, 20, F)
	buffer.writeu32(Digest, 24, G)
	buffer.writeu32(Digest, 28, H)

	return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", A, B, C, D, E, F, G, H), Digest
end

return SHA256
]===])()

local function random_bytes(length: number): string
  local result = buffer.create(length)

  for i = 1, length - 1 do
    buffer.writeu8(result, i, math.random(0, 255))
  end

  return result
end

local function sign(data: string, key: string)
  local hash_string, _ = HMAC(data, key, HMAC_SHA256.SHA256, 64)
  return hash_string
end

local function generate_api_key()
  -- this script will be obfuscated and it will have its constants encrypted, so i can just hardcode the values here
  -- note: the key must be generated ON DEMAND because it is dynamic and it gets invalid after 8 seconds

  local date_of_today = safeLoadstring([[return os.date(!%Y-%m-%dT%H:%M:%S)]], "@TAP/AES")()
  local secret_key = rgAES.new("Dh1Fmr0H5N11ExPI8KP6Iioc7jspfdV8", rgAES.modes.CTR, rgAES.pads.Pkcs7):Decrypt(
    base64.decode(buffer.fromstring("00inef+37esEJQLBK9tAAuOH2S2KVosroWyi6W+nBeGlPMT05tgmVukcOwreL4ECCUCcAaVH1JejgWbd3WsaVIpPYruRh3t2kneiiN4TIs4="),
    nil, buffer.fromstring("Z1Cvxz71xEfowdY6")))

  local signature_key = rgAES.new("Dh1Fmr0H5N11ExPI8KP6Iioc7jspfdV8", rgAES.modes.CTR, rgAES.pads.Pkcs7):Decrypt(
    base64.decode(buffer.fromstring("9g/OxnKBPhQWVvXfShz1mfzGiAfKg2UaKb1JF5EkyanCnykfZT86POAHpEdGH/ktiivL5Kf2j/Il5eD3HkNk/RZOxsECfhfqjmEFuQzAANg=")),
    nil, buffer.fromstring("Z1Cvxz71xEfowdY6")
  )

  local signature = sign(date_of_today.."|"..secret_key, buffer.tostring(signature_key))

  local iv = random_bytes(12)
  local ciphertext, tag = AES.Encrypt(
    buffer.fromstring(date_of_today.."|"..secret_key.."|"..signature),
    buffer.fromstring("Dh1Fmr0H5N11ExPI8KP6Iioc7jspfdV8"), iv
  )

  return buffer.tostring(
    base64.encode(
      buffer.fromstring(
        table.concat(
          {
            buffer.tostring(base64.encode(iv)),
            buffer.tostring(base64.encode(tag)),
            buffer.tostring(base64.encode(ciphertext))
          }
        )
      )
    )
  )
end

local function log(log_level, ...)
  print("[The Authoritative Project >> ".. log_level .. "]", ...)
end

local function main(username, key)
  log("info", "Checking user's presence...")

  if not players:GetPlayerFromUserIdAsync(players:GetUserIdFromNameAsync(username)) then
    return log("error", "User not found")
  end

  log("info", "User found, checking loader key...")

  local response = httpService:RequestAsync({
    Method = "GET",
    Url = "https://112x4.scriptlang.com/api/v3/check-loader-key",
    Body = httpService:JSONEncode({
      loader_key = key
    }),
    Headers = {
      ["Authorization"] = generate_api_key()
    }
  })

  if response.StatusCode ~= 200 then
    return log("error", "Loader key not found or you aren't authorized.")
  end

  return log("info", "Finished.")
end

return main("RazvanJTL", "hi")
