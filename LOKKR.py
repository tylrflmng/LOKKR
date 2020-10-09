from tkinter import *
import math
import string
import secrets

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

def ChoiceScreen():     #this function is the screen that appears if the user enters the correct login details
    
    Title = Label(HomePage, text="Access Granted", width=30, height=30, font=("Arial", 26, "bold italic"), fg="#ffffff", bg="#263238")
    Title.place(relx=0.5, rely=0.15, anchor="center")
    
    AddAccount1 = Button(HomePage, text="Add Account", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=AddAccountPage)
    AddAccount1.place(relx=0.5, rely=0.4, anchor="center")

    ViewAccount1 = Button(HomePage, text="View Accounts", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=ViewAccount)
    ViewAccount1.place(relx=0.5, rely=0.55, anchor="center")

    UpdateAccount = Button(HomePage, text="Update Account", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=CreateAccount)
    UpdateAccount.place(relx=0.5, rely=0.7, anchor="center")
    
    QuitButton = Button(HomePage, text="Quit", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=HomePage.destroy)
    QuitButton.place(relx=0.9, rely=0.9, anchor="center")

    HomeButton = Button(HomePage, text="Home", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=HomePage)
    HomeButton.place(relx=0.12, rely=0.9, anchor="center")

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

def AddAccountPage():   #this function is where the user adds an account that they want to be stored

    global AccountUsername
    global AccountPassword
    global GetLength
    global AddAccount
    global SiteName
    
    AddAccount = Tk()
    AddAccount.title("LOKKR")
    AddAccount.geometry("300x350")
    AddAccount.configure(background="#263238")
    Title = Label(AddAccount, text="Add Account", font=("Arial", 26, "bold italic"), fg="#ffffff", bg="#263238")
    Title.place(relx=0.5, rely=0.05, anchor="center")

    SiteName = Label(AddAccount, text="Site Name", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    SiteName.place(relx=0.5, rely=0.15, anchor="center")
    SiteName = Entry(AddAccount,width=42)
    SiteName.place(relx=0.5, rely=0.2, anchor="center")

    AccountUsernameLabel = Label(AddAccount, text="Username", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    AccountUsernameLabel.place(relx=0.5, rely=0.28, anchor="center")
    AccountUsername = Entry(AddAccount,width=42)
    AccountUsername.place(relx=0.5, rely=0.33, anchor="center")

    AccountPasswordLabel = Label(AddAccount, text="Password", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    AccountPasswordLabel.place(relx=0.5, rely=0.41, anchor="center")
    AccountPassword = Entry(AddAccount,width=42)
    AccountPassword.place(relx=0.5, rely=0.46, anchor="center")

    GenerateLabel = Label(AddAccount, text="Generate Random Password", font=("Arial", 12, "bold italic"), fg="#ffffff", bg="#263238")
    GenerateLabel.place(relx=0.5, rely=0.55, anchor="center")
    GetLength = Scale(AddAccount, from_=8, to=64, length=128, sliderlength=24, bg="#d32f2f", fg="#ffffff", orient=HORIZONTAL)
    GetLength.place(relx=0.3, rely=0.65, anchor="center")
    Generate = Button(AddAccount, text="Generate+Copy", width=12, font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=GenerateRandom)
    Generate.place(relx=0.73, rely=0.64, anchor="center")

    Submit = Button(AddAccount, text="Add Account", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=SaveAccount)
    Submit.place(relx=0.5, rely=0.8, anchor="center")

    AddAccount.mainloop()



def SaveAccount():  #this function takes the data entered in the add account window and encrypts and saves it to a text file
    key = 15

    SavedSiteName = SiteName.get()
    SavedAccountUsername = AccountUsername.get()
    SavedAccountPassword = AccountPassword.get()
    AddAccountDetails = open("Accounts.txt","a")

    EncryptSite = []
    EncryptUser = []
    EncryptPass = []

    for char in SavedSiteName:
        char = int(ord(char)) - key
        value = chr(char)
        EncryptSite.append(value)
    EncryptSite = "".join(EncryptSite)
    print(EncryptSite)

    for char in SavedAccountUsername:
        char = int(ord(char)) - key
        value = chr(char)
        EncryptUser.append(value)
    EncryptUser = "".join(EncryptUser)
    print(EncryptUser)

    for char in SavedAccountPassword:
        char = int(ord(char)) - key
        value = chr(char)
        EncryptPass.append(value)
    EncryptPass = "".join(EncryptPass)
    print(EncryptPass)

    if SavedAccountUsername and SavedAccountPassword and SavedSiteName != "":
        AddAccountDetails.write("\n")
        AddAccountDetails.write(str(EncryptSite) + "\n")
        AddAccountDetails.write(str(EncryptUser) + "\n")
        AddAccountDetails.write(str(EncryptPass) + "\n")
        AddAccountDetails.close()
        Submit = Label(AddAccount, width=19, text="Account Added", font=("Arial", 22, "bold italic"), fg="#ffffff", bg="#263238")
        Submit.place(relx=0.5, rely=0.9, anchor="center")
    else:
        SubmitStatus = Label(AddAccount, width=19, text="Missing Details", font=("Arial", 22, "bold italic"), fg="#ffffff", bg="#263238")
        SubmitStatus.place(relx=0.5, rely=0.9, anchor="center")



def GenerateRandom():   #this function generates a truly random string of any length (using lowercase + uppercase letters, numbers, and symbols)

    PasswordGen = ""
    Length = GetLength.get()
    Pool = string.ascii_letters + string.digits + string.punctuation
    for i in range(Length):
        PasswordGen += secrets.choice(Pool)
        
    CharacterPool = 0
    if re.search("[0-9]", PasswordGen):
        CharacterPool += 10
    if re.search("[A-Z]", PasswordGen):
        CharacterPool += 26
    if re.search("[a-z]", PasswordGen):
        CharacterPool += 26
    if re.search("[ !#$%&'()*+,-./:;<=>?@[\]^_`{|}~]", PasswordGen):
        CharacterPool += 32
    if math.log2(int(CharacterPool**(Length))) < 52:
        GenerateRandom()
    else:
        print(PasswordGen)
        AddAccount.clipboard_clear()
        AddAccount.clipboard_append(PasswordGen)
        CopyPassword = Label(AddAccount, text="Copied Password", font=("Arial", 10, "bold italic"), fg="#ffffff", bg="#263238")
        CopyPassword.place(relx=0.73, rely=0.72, anchor="center")

    if Length == 42:
        SubmitStatus = Label(AddAccount, width=50, text="The answer to life, the universe, and everything", font=("Arial", 9, "bold italic"), fg="#ffffff", bg="#263238")
        SubmitStatus.place(relx=0.5, rely=0.9, anchor="center")
        

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

def ViewAccount():  #this function decrypts and displays the accounts saved in the text file

    key = 15
        
    ViewAccount = Tk()
    ViewAccount.title("LOKKR")
    ViewAccount.geometry("350x900")
    ViewAccount.configure(background="#263238")

    Decrypted = ""
    with open ("Accounts.txt","rt") as Decrypt:
        for line in Decrypt:
            for element in Decrypt:
                Decrypted += "\n"
                for e in element:
                    if ord(e) != 10:
                        e = ord(e) + key
                        e = str(chr(e))
                        Decrypted += e
                print(Decrypted)

    AccountLabel = Label(ViewAccount, text=Decrypted, font=("Arial", 10, "bold italic"), fg="#ffffff", bg="#263238")
    AccountLabel.place(relx=0.5,rely=0.25, anchor="center")

    Title = Label(ViewAccount, text="Your LOKKR", font=("Arial", 26, "bold italic"), fg="#ffffff", bg="#263238")
    Title.place(relx=0.5, rely=0.025, anchor="center")

    ViewAccount.mainloop()

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

def Login():    #this function is where the user attempts to log on

    global Password
    global Username
    global Login
    PasswordCheck = ""
    
    Title = Label(HomePage, text="Log In", height=30, width=30, font=("Arial", 26, "bold italic"), fg="#ffffff", bg="#263238")
    Title.place(relx=0.5, rely=0.15, anchor="center")

    UsernameLabel = Label(HomePage, text="Username", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    UsernameLabel.place(relx=0.5, rely=0.3, anchor="center")
    Username = Entry(HomePage,width=42)
    Username.place(relx=0.5, rely=0.35, anchor="center")
    
    PasswordLabel = Label(HomePage, text="Password", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    PasswordLabel.place(relx=0.5, rely=0.41, anchor="center")
    Password = Entry(HomePage,width=42,show="*")
    Password.place(relx=0.5, rely=0.46, anchor="center")
    
    Submit = Button(HomePage, text="Submit", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=ReadPasswordFromText)
    Submit.place(relx=0.5, rely=0.6, anchor="center")

    QuitButton = Button(HomePage, text="Quit", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=HomePage.destroy)
    QuitButton.place(relx=0.9, rely=0.9, anchor="center")

    HomeButton = Button(HomePage, text="Home", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=HomePage)
    HomeButton.place(relx=0.12, rely=0.9, anchor="center")



def ReadPasswordFromText():     #this function compares the saved hash to the hash generated by the data entered on the login page
    
    try:
        PasswordAttempt = Password.get()    #Password entry from the login page
        UsernameAttempt = Username.get()   #Username entry from the login page
        HashedMasterPass = ""
        SaltValue = ""
        for char in PasswordAttempt:
            HashedMasterPass += str(ord(char))
        HashedMasterPass = int(HashedMasterPass)
        HashedMasterPass **= (128 - len(PasswordAttempt)) * 32   #the values are made large so that even a password that doesnt have many characters will still generate a long hash
        for char in UsernameAttempt:
            SaltValue += str(ord(char))
        SaltValue = int(SaltValue)
        SaltValue **= (64 - len(UsernameAttempt)) * 16    #the username is kept smaller as a username is commonly an email, and therefore longer
        HashedMasterPass = HashedMasterPass % SaltValue   #the username acts as the salt, meaning that both the username and password need to be correct. This increases security as there are more characters
        HashedMasterPass = str(hex(HashedMasterPass)[2:])[:512]   #the [2:] removes the 0x tag and the [:512] limits the hash to 512 characters so that it's impossible to reverse
        SavedPasswords = open("MasterPassword.txt","r")
        SavedMasterPass = SavedPasswords.read()
        if HashedMasterPass == SavedMasterPass:
            ChoiceScreen()
        else:
            PasswordLabel = Label(HomePage, text="Incorrect Details", font=("Arial", 24, "bold italic"), fg="#ffffff", bg="#263238")
            PasswordLabel.place(relx=0.5, rely=0.76, anchor="center")

    except ValueError:
            SubmitStatus = Label(HomePage, width=19, text="Missing Details", font=("Arial", 22, "bold italic"), fg="#ffffff", bg="#263238")
            SubmitStatus.place(relx=0.5, rely=0.76, anchor="center")

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

def CreateAccount():    #this function is only available if an account hasn't been made, and is where the user can create or update their account

    global CreatePassword
    global CreateUsername
    global CreateAccount
    
    CreateAccount = Tk()
    CreateAccount.title("LOKKR")
    CreateAccount.geometry("300x350")
    CreateAccount.configure(background="#263238")
    Title = Label(CreateAccount, text="Create / Update Account", font=("Arial", 18, "bold italic"), fg="#ffffff", bg="#263238")
    Title.place(relx=0.5, rely=0.15, anchor="center")
    
    UsernameLabel = Label(CreateAccount, text="Username", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    UsernameLabel.place(relx=0.5, rely=0.3, anchor="center")
    CreateUsername = Entry(CreateAccount,width=42)
    CreateUsername.place(relx=0.5, rely=0.35, anchor="center")

    PasswordLabel = Label(CreateAccount, text="Password", font=("Arial", 11, "bold italic"), fg="#ffffff", bg="#263238")
    PasswordLabel.place(relx=0.5, rely=0.41, anchor="center")
    CreatePassword = Entry(CreateAccount, width=42,show="*")
    CreatePassword.place(relx=0.5, rely=0.46, anchor="center")
    
    Submit = Button(CreateAccount, text="Submit", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=SavePasswordToText)
    Submit.place(relx=0.5, rely=0.55, anchor="center")

    Check = Button(CreateAccount, text="Check Password Strength", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=MasterPassStrength)
    Check.place(relx=0.5, rely=0.65, anchor="center")
    
    CreateAccount.mainloop()


    
def MasterPassStrength():   #this function checks the strength of the password entered on the create account page
    
    MasterPass = CreatePassword.get()
    
    CharacterPool = 0
    if re.search("[0-9]", MasterPass):
        CharacterPool += 10
    if re.search("[A-Z]", MasterPass):
        CharacterPool += 26
    if re.search("[a-z]", MasterPass):
        CharacterPool += 26
    if re.search("[ !#$%&'()*+,-./:;<=>?@[\]^_`{|}~]", MasterPass):
        CharacterPool += 32
    MasterPassEntropy = math.log2(int(CharacterPool**len(MasterPass)))  #The equation used to calculate the entropy is: E = R^L (Entropy = Available pool of characters ^ Length of the password)

    print(CharacterPool, len(MasterPass), MasterPassEntropy)

    if MasterPassEntropy == 0:
        CheckStrength = "No Password Entered"
    elif 0 < MasterPassEntropy <= 25:
        CheckStrength = "Very Weak"
    elif 25 < MasterPassEntropy <= 50:
        CheckStrength = "Weak"
    elif 50 < MasterPassEntropy <= 75:
        CheckStrength = "Average"
    elif 75 < MasterPassEntropy <= 100:
        CheckStrength = "Strong"
    elif 100 < MasterPassEntropy <= 150:
        CheckStrength = "Very Strong"
    elif 150 < MasterPassEntropy <= 200:
        CheckStrength = "Extreme"
    else:
        checkstrength = "Insane"

    if len(MasterPass) <= 7:
        Advice = Label(CreateAccount, width=30, text="Try using at least 8 characters", font=("Arial", 12, "bold italic"), fg="#ffffff", bg="#263238")
        Advice.place(relx=0.5, rely=0.82, anchor="center")
        if CharacterPool <= 52:
            Advice = Label(CreateAccount, width=30, text="Try using numbers and punctuation", font=("Arial", 12, "bold italic"), fg="#ffffff", bg="#263238")
            Advice.place(relx=0.5, rely=0.9, anchor="center")
    else:
        Advice = Label(CreateAccount, width=35, height=5, text=" ", font=("Arial", 12, "bold italic"), fg="#ffffff", bg="#263238")
        Advice.place(relx=0.5, rely=0.9, anchor="center")

    ShowStrength = Label(CreateAccount, width=20, text=CheckStrength, font=("Arial", 16, "bold italic"), fg="#ffffff", bg="#263238")
    ShowStrength.place(relx=0.5, rely=0.75, anchor="center")



def SavePasswordToText():   #this function hashes the data entered in the create account page, and saves the hash as a text file
    
    try:
        MasterPass = CreatePassword.get()   #Password entry from the create account page
        Username = CreateUsername.get()     #Username entry from the create account page
        HashedMasterPass = ""
        SaltValue = ""
        for char in MasterPass:
            HashedMasterPass += str(ord(char))
        HashedMasterPass = int(HashedMasterPass)
        HashedMasterPass **= (128 - len(MasterPass)) * 32
        for char in Username:
            SaltValue += str(ord(char))
        SaltValue = int(SaltValue)
        SaltValue **= (64 - len(Username)) * 16
        HashedMasterPass = HashedMasterPass % SaltValue
        HashedMasterPass = str(hex(HashedMasterPass)[2:])[:512]
        if HashedMasterPass != "0":
            print("The final hash is: ", HashedMasterPass)
            SavedPasswords = open("MasterPassword.txt","w+")
            SavedPasswords.write(HashedMasterPass)
            SavedPasswords.close()
            SubmitStatus = Label(CreateAccount, width=19, text="Saved Successfully", font=("Arial", 16, "bold italic"), fg="#ffffff", bg="#263238")
            SubmitStatus.place(relx=0.5, rely=0.85, anchor="center")
        else:
            SubmitStatus = Label(CreateAccount, width=19, text="Entries must be unique", font=("Arial", 16, "bold italic"), fg="#ffffff", bg="#263238")
            SubmitStatus.place(relx=0.5, rely=0.85, anchor="center")  
    except ValueError:
            SubmitStatus = Label(CreateAccount, width=25, text="Missing Details", font=("Arial", 16, "bold italic"), fg="#ffffff", bg="#263238")
            SubmitStatus.place(relx=0.5, rely=0.85, anchor="center")
            
#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#

HomePage = Tk()
HomePage.title("LOKKR")
HomePage.geometry("300x350")
HomePage.configure(background="#263238")
Title = Label(HomePage, text="LOKKR", font=("Arial", 44, "bold italic"), fg="#ffffff", bg="#263238")
Title.place(relx=0.5, rely=0.2, anchor="center")

Login = Button(HomePage, text="Log In", bg="#d32f2f", font=("Arial", 12), fg="#ffffff", command=Login)
Login.place(relx=0.5, rely=0.45, anchor="center")

try:
    SavedAccount = open("MasterPassword.txt","r")
except FileNotFoundError:
    AccountCreate = Button(HomePage, text="Create Account", font=("Arial", 12), bg="#d32f2f", fg="#ffffff",command=CreateAccount)
    AccountCreate.place(relx=0.5, rely=0.6, anchor="center")

QuitButton = Button(HomePage, text="Quit", font=("Arial", 12), bg="#d32f2f", fg="#ffffff", command=HomePage.destroy)
QuitButton.place(relx=0.9, rely=0.9, anchor="center")

HomePage.mainloop()

#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
