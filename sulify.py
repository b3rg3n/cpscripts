import hashlib

merNO = "test"
tradeNo = "test"
orderAmount = "133.38"
apiKey = "twedlfghgwegjwrelg"

text = merNO + tradeNo + orderAmount + apiKey

md5_hash = hashlib.md5(text.encode("utf-8")).hexdigest()

print(md5_hash)
