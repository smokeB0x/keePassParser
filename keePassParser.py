"""
keePassParser
A script to parse the header info of KeePass databases.

For now only KDBX v. 4.0 is supported

version: 1.0
Created: 24.09.26
Last modified: 24.09.26
Creator: smokeB0x

"""

import sys
import hashlib
from io import BytesIO

keePass_header_start_value = 0x9aa2d903                         # KeePass database header signature
keePass_header_end_value = bytes.fromhex("0d0a0d0a")            # KeePass database header end signature 

with open(sys.argv[1], "rb") as file:
    #Find the end of header value and offset
    entire_file = file.read()
    footer = entire_file.find(keePass_header_end_value)
    footer_offset = footer + 3                                  # +3 since this finds the start of the offset that is 4 bytes long

    entire_header = entire_file[:footer_offset + 1]

    # Find the verification hashsum after the header and verify the header
    file.seek(footer_offset + 1)
    verification_hashsum = file.read(32)                        # Reads the 32 bytes directly following the header
    header_hashsum = hashlib.sha256(entire_header).digest()

    if verification_hashsum == header_hashsum:
        verification = "Match"
    else: 
        verification = "Not a match"

    # Extract the 32 bytes after the verification hashsum
    header_hmac = file.read(32)

    # Fixed header bytes start
    file.seek(0)                                               # Reset the position to byte 0 (it was moved to the end for finding the footer)
    header = int.from_bytes(file.read(4), "little")
    

    if header != keePass_header_start_value:  
        print("KeePass database header signature not found")
        sys.exit()

    file_signature = int.from_bytes(file.read(4), "little")

    if file_signature == 0xb54bfb67:                            # KeePass version 2 or later
        keepass_version = "Version 2 or later"

    elif file_signature == 0xb54bfb66:                          # KeePass version 2.x pre-release/beta
        keepass_version = "2.x pre-release/beta"

    elif file_signature == 0xb54bfb65:                          # KeePass versaion 1.0 up to 2.0
        keepass_version = "Earlier than version 2"

    else:
        keepass_version = "Unknown"

    minor_version = int.from_bytes(file.read(2), "little")      # KDBX minor version
    major_version = int.from_bytes(file.read(2), "little")      # KDBX major version

    kdbx_version = f"{major_version}.{minor_version}"
    
    # Variable header bytes start
     
    # ID 1, 5, 6 8 9 10 were used in previous versions of the KDBX
    
    # while loop that reads through the file in the spesified format - does this 12 times or until the terminator "0x00" is found. Adds the items to a list.
    i = 0
    ID_list = []
    while i != 12:
        ID = int.from_bytes(file.read(1))
        ID_list.append(ID)
        ID_length = int.from_bytes(file.read(4), "little")
        ID_list.append(ID_length)
        ID_value = (bytes.hex(file.read(ID_length)))
        ID_list.append(ID_value)

        if ID == 0x00:
            break
        i = i + 1

    IDs = ID_list[0::3]                        # IDs = the first of every 3-value group
    length = ID_list[1::3]                     # Lenghth = the second of every 3-value group
    value = ID_list[2::3]                      # Value = the third of every 3-value group

    # Read through the list of values with variable offsets and categorize them

    unsupported_values = []                    # Placeholder for the unsupported values list, if there are none
    for field_id, lengths, values in zip(IDs, length, value):
        if field_id == 0x02:
            cipher_ID = int.from_bytes(bytes.fromhex(values))
            if cipher_ID == 0x31C1F2E6BF714350BE5805216AFC5AFF:
                cipher_type = "AES-256"
            elif cipher_ID == 0xD6038A2B8B6F4CB5A524339A31DBB59A:
                cipher_type = "ChaCha20"
            else:
                cipher_type = "Unknown"
        elif field_id == 0x03:
            compression_flag = int.from_bytes(bytes.fromhex(values), "little")
            if compression_flag == 0x00:
                 compression_used = "none"
            elif compression_flag == 0x01:
                compression_used = "GZip"
            else:
                compression_used = "Unknown"
        elif field_id == 0x04:
            master_seed = values
        elif field_id == 0x0B:
            kdf_parameters = values
        elif field_id == 0x07:
            encryption_IV = values
        elif field_id == 0x00:
            end_of_header_value = values
        else:
            unsupported_values.append(field_id)

# KDF paramaeters parsing        

kdf_stream = BytesIO(bytes.fromhex(kdf_parameters))             # Convert the KDF-parameters in the variable to a readable byte stream

version_marker_minor = int.from_bytes(kdf_stream.read(1))
version_marker_major = int.from_bytes(kdf_stream.read(1))

i = 0
kdf_param_list = []
while i != 12:                                                       # Set the number 12 because why not?
    kdf_type_code = int.from_bytes(kdf_stream.read(1))
    kdf_name_length = int.from_bytes(kdf_stream.read(4), "little")
    kdf_name = kdf_stream.read(kdf_name_length).decode("utf-8")
    kdf_param_list.append(kdf_name)
    kdf_value_length = int.from_bytes(kdf_stream.read(4), "little")
    kdf_value = (bytes.hex(kdf_stream.read(kdf_value_length)))
    kdf_param_list.append(kdf_value)

    if kdf_type_code == 0x00:                                                   # Terminator byte = 0x00
        break
    i = i + 1

kdf_name_in_list = kdf_param_list[0::2]                                         # KDF name = the first of every 2-value group
kdf_value_in_list = kdf_param_list[1::2]                                        # KDF value = the seccond of every 2-value group


aes_kdf_rounds = "N/A"                                                          # Placeholder if that value is not used
aes_kdf_salt = "N/A"                                                            # Placeholder if that value is not used
argon2_version = "N/A"                                                          # Placeholder if that value is not used
argon2_iterations = "N/A"                                                       # Placeholder if that value is not used
argon2_memory = "N/A"                                                           # Placeholder if that value is not used
argon2_parallelism = "N/A"                                                      # Placeholder if that value is not used

unsupported_kdf_values = []
for name, value in zip(kdf_name_in_list, kdf_value_in_list):
    if name == "$UUID":
        encryption_kdf_value = int.from_bytes(bytes.fromhex(value))
        if encryption_kdf_value == 0xC9D9F39A628A4460BF740D08C18A4FEA:
            kdf_encryption_type = "AES-KDF"
        elif encryption_kdf_value == 0xEF636DDF8C29444B91F7A9A403E30A0C:
            kdf_encryption_type = "Argon2d"
        elif encryption_kdf_value == 0x9E298B1956DB4773B23DFC3EC6F0A1E6:
            kdf_encryption_type = "Argon2id"
        else:
            kdf_encryption_type = "Unknown"
    elif name == "R":
        aes_kdf_rounds = int.from_bytes(bytes.fromhex(value), "little")         # Convert the round count from hex to decimal
    elif name == "S":
        aes_kdf_salt = value
    elif name == "V":
        argon2_version = int.from_bytes(bytes.fromhex(value), "little")
        if argon2_version == 0x10:
            argon2_version_number = "1.0"
        elif argon2_version == 0x13:
            argon2_version_number ="1.3 (recommended)"
        else: 
            argon2_version_number = "unknown"
    elif name == "I":
        argon2_iterations = int.from_bytes(bytes.fromhex(value), "little")
    elif name == "M":
        argon2_memory = int.from_bytes(bytes.fromhex(value), "little")
    elif name == "P":
        argon2_parallelism = int.from_bytes(bytes.fromhex(value), "little")
    else:
        unsupported_kdf_values.append(name)


# Print everything 

print(f"######################")
print(f"# Header and version #")
print(f"######################")
print(f"Filename: {sys.argv[1]}")
print(f"Keepass header: {header:08x}  - This matches a KeePass database header")
print(f"KeePass version: {keepass_version}")   
print(f"KDBX version: {kdbx_version}")
print(f"End of header: {bytes.hex(keePass_header_end_value)} found at offset {footer_offset}")
print(f"Header hashsum: {bytes.hex(header_hashsum)}")
print(f"Verification hashsum of the header: {bytes.hex(verification_hashsum)}")
print(f"Verfification: {verification}\n")
#print(f"#################")
#print(f"# Entire header #")
#print(f"#################")
#print(f"{bytes.hex(entire_header)}\n")
print(f"##########################")
print(f"# Encryption information #")
print(f"##########################")
print(f"Cipher ID: {cipher_ID}. Cipher type is: {cipher_type}")
print(f"Compression flag: {compression_flag}. Compression used: {compression_used}")
print(f"Master seed: {master_seed}")
#print(f"KDF paramaeters: {kdf_parameters}")
print(f"Encryption IV: {encryption_IV}")
print(f"Variable offsets - other values: {unsupported_values}")
print(f"32 byte header HMAC: {bytes.hex(header_hmac)}\n")
print(f"##################")
print(f"# KDF-parameters #")
print(f"##################")
print(f"KDF version marker (should be 1.0): {version_marker_major}.{version_marker_minor}")
print(f"KDF encryption type: {kdf_encryption_type}")
if kdf_encryption_type == "AES-KDF":
    print(f"Round count/iterations: {aes_kdf_rounds}")
    print(f"AES-KDF salt/seed: {aes_kdf_salt}")
elif kdf_encryption_type == "Argon2d" or kdf_encryption_type == "Argon2id":
    print(f"Argon2 version value: {hex(argon2_version)}")
    print(f"Argon2 version: {argon2_version_number}")
    print(f"Argon2 salt: {aes_kdf_salt}")
    print(f"Argon2 Iterations: {argon2_iterations}")
    print(f"Argon2 Memory, in bytes: {argon2_memory}")
    print(f"Argon2 parallelism: {argon2_parallelism}")
print(f"Found KDF-values that is not supported: {unsupported_kdf_values}")
#print(f"\nKDF-values: {kdf_param_list}")