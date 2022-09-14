# Enigma Template Code for CNU Information Security 2022
# Resources from https://www.cryptomuseum.com/crypto/enigma

# This Enigma code implements Enigma I, which is utilized by 
# Wehrmacht and Luftwaffe, Nazi Germany. 
# This version of Enigma does not contain wheel settings, skipped for
# adjusting difficulty of the assignment.

from copy import deepcopy
from ctypes import ArgumentError

# Enigma Components
ETW = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

WHEELS = {
    "I" : {
        "wire": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        "turn": 16,
        "r":0
    },
    "II": {
        "wire": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "turn": 4,
        "r":0
    },
    "III": {
        "wire": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "turn": 21,
        "r":0
    }
}

UKW = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"
}

# Enigma Settings
SETTINGS = {
    "UKW": None,
    "WHEELS": [],
    "WHEEL_POS": [],
    "ETW": ETW,
    "PLUGBOARD": []
}

def apply_settings(ukw, wheel, wheel_pos, plugboard):
    if not ukw in UKW:
        raise ArgumentError(f"UKW {ukw} does not exist!")
    SETTINGS["UKW"] = UKW[ukw]

    wheels = wheel.split(' ')
    for wh in wheels:
        if not wh in WHEELS:
            raise ArgumentError(f"WHEEL {wh} does not exist!")
        SETTINGS["WHEELS"].append(WHEELS[wh])

    wheel_poses = wheel_pos.split(' ')
    for wp in wheel_poses:
        if not wp in ETW:
            raise ArgumentError(f"WHEEL position must be in A-Z!")
        SETTINGS["WHEEL_POS"].append(ord(wp) - ord('A'))
    
    plugboard_setup = plugboard.split(' ')
    for ps in plugboard_setup:
        if not len(ps) == 2 or not ps.isupper():
            raise ArgumentError(f"Each plugboard setting must be sized in 2 and caplitalized; {ps} is invalid")
        SETTINGS["PLUGBOARD"].append(ps)

# Enigma Logics Start

# Plugboard
def pass_plugboard(input):
    for plug in SETTINGS["PLUGBOARD"]:
        if str.startswith(plug, input):
            return plug[1]
        elif str.endswith(plug, input):
            return plug[0]

    return input

# ETW
def pass_etw(input):
    return SETTINGS["ETW"][ord(input) - ord('A')]

# Wheels
def pass_wheels(input, reverse = False):
    # Implement Wheel Logics
    # Keep in mind that reflected signals pass wheels in reverse order
    if (reverse==False):
        temp=SETTINGS["WHEELS"][0]["wire"][ord(input)-ord('A')]
        temp=SETTINGS["WHEELS"][1]["wire"][ord(temp) - ord('A')]
        temp=SETTINGS["WHEELS"][2]["wire"][ord(temp) - ord('A')]
        return temp
    elif (reverse==True):
        temp = SETTINGS["WHEELS"][2]["wire"][ord(input) - ord('A')]
        temp = SETTINGS["WHEELS"][1]["wire"][ord(temp) - ord('A')]
        temp = SETTINGS["WHEELS"][0]["wire"][ord(temp) - ord('A')]
        return temp
    return input

# UKW
def pass_ukw(input):
    return SETTINGS["UKW"][ord(input) - ord('A')]

# Wheel Rotation
def rotate_wheels():
    # Implement Wheel Rotation Logics
    turn0 = SETTINGS["WHEELS"][0]["turn"]
    SETTINGS["WHEELS"][0]["wire"] = SETTINGS["WHEELS"][0]["wire"][turn0:26] + SETTINGS["WHEELS"][0]["wire"][0:turn0]
    WHEELS["I"]["r"] += turn0
    if (SETTINGS["WHEELS"][0]["r"] / 26 > 1):
        SETTINGS["WHEELS"][0]["r"] %= 26
        turn1=SETTINGS["WHEELS"][1]["turn"]
        SETTINGS["WHEELS"][1]["wire"] = SETTINGS["WHEELS"][1]["wire"][turn1:26] + SETTINGS["WHEELS"][1]["wire"][0:turn1]
        SETTINGS["WHEELS"][1]["r"] += turn1
        if (SETTINGS["WHEELS"][1]["r"] / 26 > 1):
            SETTINGS["WHEELS"][1]["r"] %= 26
            turn2=SETTINGS["WHEELS"][2]["turn"]
            SETTINGS["WHEELS"][2]["wire"] = SETTINGS["WHEELS"][2]["wire"][turn2:26] + SETTINGS["WHEELS"][2]["wire"][0:turn2]
            SETTINGS["WHEELS"][2]["r"] +=turn2

# Enigma Exec Start
plaintext = input("Plaintext to Encode: ")
ukw_select = input("Set Reflector (A, B, C): ")
wheel_select = input("Set Wheel Sequence L->R (I, II, III): ")
wheel_pos_select = input("Set Wheel Position L->R (A~Z): ")
plugboard_setup = input("Plugboard Setup: ")

apply_settings(ukw_select, wheel_select, wheel_pos_select, plugboard_setup)

for ch in plaintext:
    rotate_wheels()

    encoded_ch = ch

    encoded_ch = pass_plugboard(encoded_ch)
    encoded_ch = pass_etw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch)
    encoded_ch = pass_ukw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch, reverse = True)
    encoded_ch = pass_plugboard(encoded_ch)

    print(encoded_ch, end='')
