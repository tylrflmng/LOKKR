Username = input("Enter Username ")
MasterPass = input("Enter Password ")

total = ""
SaltValue = ""
converted_total = ""
for char in MasterPass:
    total += str(ord(char))
total = int(total)
total **= (128 - len(MasterPass)) * 32
for char in Username:
    SaltValue += str(ord(char))
SaltValue = int(SaltValue)
SaltValue **= (64 - len(Username)) * 16
total = total % SaltValue
total = str(hex(total)[2:])[:512]
print("The final hash is: ", total)

