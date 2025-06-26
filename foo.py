r = reader.events()
e = next(r)
e = next(r)

print(e.foo)
print(e.raw())
print(e.skb.packet)
